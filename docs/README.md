# Website

This website is built using [Docusaurus](https://docusaurus.io/), a modern static website generator.

## Installation

```bash
npm install
```

## Local Development

```bash
npm start
```

This command starts a local development server and opens up a browser window. Most changes are reflected live without having to restart the server.

## Build

```bash
npm run build
```

This command generates static content into the `build` directory and can be served using any static contents hosting service.

## Deployment

Deployment is automated via GitHub Actions. When changes are pushed to the `main` branch, the documentation is automatically built and deployed to GitHub Pages.

To manually deploy:

```bash
GIT_USER=<Your GitHub username> npm run deploy
```
