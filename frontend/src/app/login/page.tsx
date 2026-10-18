import { SignInView } from "@/components/auth/SignInView";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Sign In — AttackPath Security Platform",
  description:
    "Sign in to the AttackPath multi-hop attack path discovery, evidence explanation, and remediation simulation workspace.",
};

export default function LoginPage() {
  return <SignInView />;
}
