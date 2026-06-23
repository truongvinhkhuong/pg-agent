# -*- coding: utf-8 -*-
"""Google Colab bootstrap.

TWO paths — pick by who is running:

(A) REVIEWER / PUBLIC  (default, NO token, fully reproducible)
    The academic artifact runs end-to-end on the mock + synthetic data. Reviewers
    need NOTHING private. This is the path the paper's results depend on.

(B) INTERNAL VALIDATION  (token required, NOT for reviewers)
    Pulls the real private pco_core to validate the same guard on real models.
    Reads the token from Colab Secrets (userdata) — never hardcode it.
"""

import subprocess


def public_path():
    """(A) Clone only the public repo and run the benchmark on the mock."""
    subprocess.run(
        ["git", "clone", "--depth", "1",
         "https://github.com/<org>/pg-agent.git"],
        check=True,
    )
    print("Public artifact ready. Run the benchmark on the mock — no token needed.")


def internal_validation_path():
    """(B) INTERNAL ONLY — inject a short-lived token to fetch the private submodule.

    Token handling rules:
      * read from Colab Secrets (userdata), never hardcode;
      * use a fine-grained, read-only, short-lived PAT scoped to ONE private repo;
      * configure via url.insteadOf so the token is not written into .gitmodules;
      * clear notebook outputs before sharing — this path must not run in a shared
        notebook with saved output.
    """
    from google.colab import userdata  # noqa: E402  (Colab-only import)

    token = userdata.get("GITHUB_TOKEN")
    if not token:
        raise RuntimeError("GITHUB_TOKEN missing in Colab Secrets.")

    # Rewrite HTTPS auth globally and transiently; do NOT bake the token into URLs.
    subprocess.run(
        ["git", "config", "--global",
         f"url.https://x-access-token:{token}@github.com/.insteadOf",
         "https://github.com/"],
        check=True,
    )
    try:
        # In the PRIVATE checkout, pg-agent is a submodule and pco_core is the
        # real business code mounted for validation.
        subprocess.run(["git", "submodule", "update", "--init", "--recursive"], check=True)
    finally:
        # Always remove the credential rewrite afterwards.
        subprocess.run(
            ["git", "config", "--global", "--unset",
             "url.https://x-access-token:" + token + "@github.com/.insteadOf"],
            check=False,
        )
    print("Internal validation checkout ready.")


if __name__ == "__main__":
    public_path()
