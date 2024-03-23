# --------------------------------------------------------------------- base ---

FROM golang:1.22 as base

ARG APP_VERSION=latest

ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0

RUN mkdir -p /opt/app
WORKDIR /opt/app

# RUN git clone https://github.com/cruxstack/cognito-custom-message-sender-go.git .
# RUN if [ "$APP_VERSION" != "latest" ] ; then git checkout $APP_VERSION ; fi
COPY . .

RUN go mod download \
    && go build -o bootstrap -buildvcs=false


ARG SERVICE_OPA_POLICY_ENCODED=cGFja2FnZSBjb2duaXRvX2N1c3RvbV9zZW5kZXJfc21zX3BvbGljeQoKcmVzdWx0IDo9IFtd
RUN echo "$SERVICE_OPA_POLICY_ENCODED" | base64 -d > /opt/app/policy.rego


# ------------------------------------------------------------------ package ---

FROM alpine:latest as package

COPY --from=base /opt/app/policy.rego /opt/app/dist/policy.rego
COPY --from=base /opt/app/bootstrap /opt/app/dist/bootstrap

RUN apk add zip \
    && cd /opt/app/dist \
    && zip -r /tmp/package.zip .
