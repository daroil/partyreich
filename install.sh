#!/bin/bash

# Update the package list
sudo apt update

## Download and install nvm:
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.2/install.sh | bash
#
## in lieu of restarting the shell
\. "$HOME/.nvm/nvm.sh"
#
## Download and install Node.js:
nvm install 22
#
## Verify the Node.js version:
node -v # Should print "v22.15.0".
nvm current # Should print "v22.15.0".
#
## Verify npm version:
npm -v # Should print "10.9.2".


# Install build tools (required for some npm packages, especially those using native addons)
echo "Installing build tools..."
sudo apt install -y build-essential

# If you are using a project that requires npm packages, uncomment and run the following lines:
echo "Installing necessary npm packages..."
npm install 

echo "Installation of the npm and node js complete!"
