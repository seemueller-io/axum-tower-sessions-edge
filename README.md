# axum-tower-sessions-edge
Formerly `zitadel-session-worker`

> Original commit history availble by request.

## Development History
Below is a curated list of key milestones in the development of this project, reflecting significant updates and features added over time (reverse-chronological)
- Implement new session functionality - 5/9/25
- Add error handlers for introspection - 5/9/25
- Improve error handling for smoother operation - 5/8/25
- Ensure compatibility with Safari - 5/8/25
- Deploy latest changes - 5/8/25
- Deploy updates - 5/8/25
- Evaluate next steps for project direction - 5/6/25
- Enable effective cache usage - 5/6/25
- Update introspection handler to prioritize cache - 5/6/25
- Revise session expiry and add proxy status API tests - 5/6/25
- Confirm basic functionality of recent changes - 5/6/25
- Resolve issues in _cyberspace_ context (placeholder for explicatives) - 5/5/25
- Complete full login cycle - 5/5/25
- Add Cloudflare introspection cache - 5/5/25
- Implement minor updates - 5/3/25
- Enhance Cloudflare session storage backend - 4/30/25
- Fix Tower session extractor and refactor session creation - 4/30/25
- Perform code cleanup - 4/30/25
- Optimize for API application compatibility - 4/29/25
- Establish basic session functionality - 4/29/25
- Make progress on key features - 4/29/25
- Experiment with redirect configurations - 4/29/25
- Debug callback issues; session store functional in callback - 4/28/25
- Continue work on callback implementation - 4/28/25
- Complete proxy target compilation - 4/28/25
- Reintroduce session middleware - 4/28/25
- Remove sensitive secrets from codebase - 4/28/25
- Implement dynamic incoming URL handling - 4/28/25
- Correct KV storage naming - 4/27/25
- Add callback functionality - 4/27/25
- Introduce project structure improvements - 4/26/25
- Address client returning 403 error - 4/26/25
- Advance project development - 4/26/25
- Clean up code and rename functions for clarity - 4/24/25
- Integrate session manager and introspection features - 4/24/25
- Add root path configuration - 2/2/25
- Fetch provider metadata successfully - 2/2/25
- Update type definition for introspected user - 2/1/25
- Confirm application runs successfully - 2/1/25
- Reintegrate test suite - 2/1/25
- Achieve successful compilation - 2/1/25
- Create random development checkpoint - 2/1/25
- Initialize project repository - 2/1/25


> ⚠️ **WARNING**: This project is currently in development and **NOT** production-ready. Use at your own risk. It may
> contain bugs, security vulnerabilities, or incomplete features. This should
> serve as a starting point for anyone building similar technology. All feedback is welcome.

A Rust Cloudflare Worker that provides authentication and session management for web applications using ZITADEL as the identity provider. It adopts the implementation for oauth2 token introspection from [smartive/zitadel-rs](https://github.com/smartive/zitadel-rust). 

## Overview

This project is a Rust-based Cloudflare Worker that acts as an authentication proxy for web applications. It handles:

- oauth2/oidc w/PKCE via Zitadel
- Session management using Cloudflare KV storage
- Token introspection and validation
- Proxying authenticated requests to backend services

When deployed, the worker sits between your users and your application services. It:
1. Intercepts incoming requests
2. Verifies if the user has a valid session
3. If not, redirects to ZITADEL for authentication
4. After successful authentication, creates a session and proxies the request to your service
5. For subsequent requests, validates the session and proxies authenticated requests


> **Note**: Caches are used by the introspection and session modules. They prevent excessive r/w.
 
## Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (latest stable version)
- LLVM and clang
- [Bun](https://bun.sh/) JavaScript runtime
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/) for Cloudflare Workers development
- ZITADEL Administrator Access

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd zitadel-session-worker
   ```

2. Install dependencies:
   ```bash
   # Install JavaScript dependencies
   bun install
   ```

## Configuration

> **Note**: There is a docker compose file with Zitadel in this repository that can be used for testing.

### Environment Variables

Create a `.dev.vars` file in the project root with the following variables:

```
CLIENT_ID="your-client-id"
CLIENT_SECRET="your-client-secret"
AUTH_SERVER_URL="your-zitadel-instance-url"
ZITADEL_ORG_ID="your-organization-id"
ZITADEL_PROJECT_ID="your-project-id"
APP_URL="http://localhost:3000"
DEV_MODE="true"
```

### Wrangler Configuration

- `wrangler.jsonc` - Base configuration

## Development

### Running Locally

```bash
# Start the development server
bun run dev
```

This will start the worker on `localhost:3000`.

### Building

```bash
# Build the project
cargo clean && cargo install -q worker-build && worker-build --release
```

## Deployment

### Deploying to Cloudflare

```bash
# Deploy to development environment
bun run deploy:dev

# Deploy with updated secrets
bun run deploy:dev:secrets
```

### Viewing Logs

```bash
# View logs from the deployed worker
bun run tail:dev
```

## Integration with Your Application

To integrate this worker with your existing application:

1. **Configure Cloudflare**:
   - Set up a Cloudflare Worker route that points to your application domain
   - Deploy this worker to that route

2. **Configure ZITADEL**:
   - Create an application in ZITADEL
   - Configure the redirect URI to `https://your-worker-domain/login/callback`
   - Get the client ID and client secret

3. **Configure this Worker**:
   - Update the environment variables with your ZITADEL credentials
   - Set the `APP_URL` to your application's URL
   - Set an http route in `wrangler.jsonc`

4. **Access Control**:
   - The worker will automatically handle authentication
   - Your application will receive authenticated requests with user information
   - You can access user information via the `/api/whoami` endpoint

## Testing

The project uses Rust's built-in testing framework with tokio for async tests.

```bash
# Run all tests
cargo test
```

### Adding New Tests

1. For unit tests, add them to the `tests` module in the relevant source file
2. For async tests, use the `#[tokio::test]` attribute
3. Follow the existing pattern of testing both success and error cases
4. Mock external dependencies when necessary

## Debugging

1. For local development, use `console_log!` macros to output debug information
2. View logs in the wrangler development console
3. For deployed workers, use `bun run tail:dev` to stream logs
4. Check the `/api/whoami` endpoint to verify user authentication and session data

## Project Structure

- `src/` - Rust source code
  - `api/` - API endpoints and routing
  - `axum_introspector/` - Axum framework integration for token introspection
  - `credentials/` - Credential management
  - `oidc/` - OpenID Connect implementation
  - `session_storage/` - Session storage implementations
  - `utilities.rs` - Utility functions
  - `lib.rs` - Main entry point and worker setup

## Contributing

Contributions to this project are welcome! Here are some guidelines:

1. **Fork the repository** and create your branch from `main`
2. **Install dependencies** and ensure you can build the project
3. **Make your changes** and add or update tests as necessary
4. **Ensure tests pass** by running `cargo test`
5. **Format your code** with `cargo fmt`
6. **Submit a pull request** with a clear description of your changes

### Code Style

- Follow Rust's standard code style and idioms
- Use `cargo fmt` to format code
- Use `cargo clippy` for linting

## Acknowledgements

This project is made possible thanks to:

- **ZITADEL**: For providing the robust identity management platform that powers this authentication proxy
- **Smartive**: For [zitadel-rs](https://github.com/smartive/zitadel-rust) 
- **Cloudflare**: For their Workers platform and KV storage solution
- **Fermyon Spin** https://github.com/fermyon/http-auth-middleware (Reference implementation)
- **Open Source Community**: For the various dependencies and tools that make this project possible:
    - The Rust ecosystem and its crates
    - The Axum web framework
    - The Tower middleware ecosystem
    - Various other open-source projects listed in our dependencies

I appreciate the hard work and dedication of all the developers and organizations that contribute to the open-source
ecosystem.


## License

MIT License

Copyright (c) 2025 Geoff Seemueller

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
