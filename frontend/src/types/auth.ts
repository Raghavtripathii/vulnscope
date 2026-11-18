export interface RegisterPayload {
  email: string;
  password: string;
}

export interface LoginPayload {
  email: string;
  password: string;
}

export interface User {
  id: number;
  email: string;
}

export interface Me {
  id: number;
  email: string;
  is_teacher: boolean;
}