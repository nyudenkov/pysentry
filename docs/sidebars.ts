import type { SidebarsConfig } from "@docusaurus/plugin-content-docs";

const sidebars: SidebarsConfig = {
  docs: [
    "intro",
    "why-scan",
    {
      type: "category",
      label: "Getting Started",
      items: ["getting-started/installation", "getting-started/quickstart"],
    },
    {
      type: "category",
      label: "Configuration",
      items: [
        "configuration/config-files",
        "configuration/environment-variables",
        "configuration/cli-options",
      ],
    },
    "troubleshooting",
  ],
};

export default sidebars;
