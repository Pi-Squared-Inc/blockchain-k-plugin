ARG K_VERSION

# Use the prebuilt base image with the specified version
FROM  ghcr.io/pi-squared-inc/ulm-k:ubuntu-jammy-${K_VERSION}

ARG LLVM_VERSION

RUN    apt-get update             \
    && apt-get upgrade --yes      \
    && apt-get install --yes      \
            autoconf              \
            cargo                 \
            clang-${LLVM_VERSION} \
            cmake                 \
            curl                  \
            libsecp256k1-dev      \
            libssl-dev            \
            libtool

ARG USER=github-user
ARG GROUP=${USER}
ARG USER_ID=1000
ARG GROUP_ID=${USER_ID}
RUN groupadd -g ${GROUP_ID} ${GROUP} && useradd -m -u ${USER_ID} -s /bin/sh -g ${GROUP} ${USER}

USER ${USER}:${GROUP}

ENV PATH=/home/${USER}/.local/bin:${PATH}
RUN    pip install pytest \
    && pytest --version
RUN    curl -sSL https://install.python-poetry.org | python3 - \
    && poetry --version
