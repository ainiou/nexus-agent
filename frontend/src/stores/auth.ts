/**
 * 认证状态 —— 全局唯一的登录态持有者。
 *
 * Token 策略（与 ep17 后端语义对齐）：
 * - access_token 放内存（store），刷新页面即失效 → 用 refresh_token 静默续期；
 * - refresh_token 放 localStorage（key: nx.refresh），登出/过期时清除；
 * - 请求层通过 bindAuthHooks 与本 store 解耦，避免循环依赖。
 */
import { create } from 'zustand';
import { bindAuthHooks, http, refreshAccessToken } from '@/lib/request';
import type { LoginReq, RegisterReq, TokenPair, User } from '@/types/auth';

interface AuthState {
  /** 内存中的 access token */
  accessToken?: string;
  user?: User;
  /** 是否已完成首次启动的会话恢复（防路由守卫闪跳登录页） */
  bootstrapped: boolean;

  bootstrap: () => Promise<void>;
  login: (req: LoginReq) => Promise<void>;
  register: (req: RegisterReq) => Promise<void>;
  logout: () => Promise<void>;
  setToken: (token: string) => void;
  /** 登录态彻底过期：清 token，路由守卫自动跳登录页（由请求层回调） */
  expire: () => void;
}

const REFRESH_KEY = 'nx.refresh';

/** 会话恢复单飞：StrictMode 双挂载/并发调用共享同一次恢复，避免并发轮换 refresh token */
let bootstrapPromise: Promise<void> | null = null;

export const useAuth = create<AuthState>((set) => ({
  accessToken: undefined,
  user: undefined,
  bootstrapped: false,

  /** 应用启动时调用：用 localStorage 里的 refresh_token 恢复会话 */
  bootstrap: () => {
    bootstrapPromise ??= (async () => {
      const refreshToken = localStorage.getItem(REFRESH_KEY);
      if (refreshToken) {
        // 走请求层单飞刷新（新 refresh_token 由请求层写回 localStorage，
        // 新 access_token 经 onTokenRefreshed 注入本 store），不再直连 http.post
        const accessToken = await refreshAccessToken();
        if (accessToken) {
          try {
            const user = await http.get<User>('/me');
            set({ accessToken, user });
          } catch {
            localStorage.removeItem(REFRESH_KEY);
            set({ accessToken: undefined });
          }
        } else {
          localStorage.removeItem(REFRESH_KEY);
        }
      }
      set({ bootstrapped: true });
    })();
    return bootstrapPromise;
  },

  login: async (req) => {
    const pair = await http.post<TokenPair>('/auth/login', req);
    localStorage.setItem(REFRESH_KEY, pair.refresh_token);
    set({ accessToken: pair.access_token });
    const user = await http.get<User>('/me');
    set({ user });
  },

  register: async (req) => {
    await http.post<{ id: number }>('/auth/register', req);
  },

  logout: async () => {
    try {
      await http.post('/auth/logout');
    } finally {
      localStorage.removeItem(REFRESH_KEY);
      set({ accessToken: undefined, user: undefined });
    }
  },

  setToken: (token) => set({ accessToken: token }),

  expire: () => {
    localStorage.removeItem(REFRESH_KEY);
    set({ accessToken: undefined, user: undefined });
  },
}));

// ---- 与请求层对接（一次性注入，避免循环依赖） ----
bindAuthHooks(
  () => useAuth.getState().accessToken,
  () => useAuth.getState().expire(),
  (t) => useAuth.getState().setToken(t),
);
