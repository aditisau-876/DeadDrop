
import type { ReactNode } from "react";

interface PageProps {
  title: string;
  sub: string;
  children?: ReactNode;
}

export function Page({ title, sub, children }: PageProps) {
  return (
    <div className="page">
      <div className="page-heading">
        <small>{sub}</small>
        <h1>{title}</h1>
      </div>

      <div className="page-content">{children}</div>
    </div>
  );
}
