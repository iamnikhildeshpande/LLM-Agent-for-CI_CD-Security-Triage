from orchestrator import run_triage_and_raise

if __name__ == "__main__":
    result = run_triage_and_raise(
        build_id="build-1234",
        artifacts_url="https://ci.example.com/job/1234/artifact/",
        assignment_group="DevSecOps",
        short_app_name="Checkout"
    )
    print(result)