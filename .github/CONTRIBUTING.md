## Contributing

This project welcomes contributions and suggestions. Most contributions require you to
agree to a Contributor License Agreement (CLA) declaring that you have the right to,
and actually do, grant us the rights to use your contribution. For details, visit
https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need
to provide a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions provided by the bot. You will only need to do this once across all repositories using our CLA.

Note that we only accept pull requests from forks so please fork the CCF repository before making any changes. You should contribute your changes on a branch on that fork and create a pull request on the [microsoft/CCF repository](https://github.com/microsoft/CCF/compare) from there.

All pull requests must pass a suite of CI tests before they are merged.
Test commands are defined in [`test.yml`](https://github.com/microsoft/CCF/blob/master/.azure-pipelines-templates/test.yml), so you can locally repeat any tests which fail.

Code must also meet format requirements enforced by [`checks.yml`](https://github.com/microsoft/CCF/blob/master/.azure-pipelines-templates/checks.yml), which can be checked locally by running [`scripts/ci-checks.sh`]. Some formatting issues can be fixed automatically by running [`scripts/ci-checks.sh -f`].

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/)
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
