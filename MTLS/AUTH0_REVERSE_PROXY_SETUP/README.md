### Steps for Configuring Custom Domains with Self-Managed Certificates in Auth0 and Using NGINX as the Reverse proxy

#### 1. Setting Up Custom Domains in Auth0

1. **Access Auth0 Dashboard**:
   - Go to the Auth0 Dashboard and navigate to (https://manage.auth0.com/dashboard/<rebion>/<tennant>/tenant/custom_domains) > **Custom Domains**.

2. **Add a Custom Domain**:
   - Enter your custom domain (e.g., `subdomain.domain.com`).
   - Select **Self-managed Certificates** as the certificate type.
   - Click **Add Domain**.

3. **Verify Domain Ownership**:
   - Auth0 will provide a TXT record for domain verification.
   - Log in to your domain registrar's DNS management console and add the TXT record provided by Auth0.
   - After adding the TXT record, return to the Auth0 dashboard and click **Verify**.
   - Once verified, Auth0 will display a `cname-api-key` and Origin Domain Name which you need to configure your reverse proxy.

For detailed instructions, visit the [Auth0 Custom Domains documentation](https://auth0.com/docs/customize/custom-domains/self-managed-certificates).

#### 2. Configuring NGINX as a Reverse Proxy

You will use NGINX to proxy requests to Auth0 and handle SSL/TLS termination with Let's Encrypt certificates.

1. **Install Certbot for Let's Encrypt**:
   - Install Certbot to manage SSL certificates automatically.
   - Use the following commands to install Certbot and the NGINX plugin:
     ```bash
     sudo apt update
     sudo apt install certbot python3-certbot-nginx
     ```

2. **Obtain SSL Certificates**:
   - Run Certbot to obtain SSL certificates for your domains:
     ```bash
     sudo certbot --nginx -d subdomain.domain.com -d mtls.subdomain.domain.com
     ```

3. **Configure NGINX for the Main Domain** (`subdomain.domain.com`):
   - Create or edit the NGINX configuration file for your main domain, typically located at `/etc/nginx/sites-available/subdomain`.
   - Use the following configuration:
     ```nginx
     server {
         listen 443 ssl;
         server_name subdomain.domain.com;

         # SSL/TLS certificates
         ssl_certificate /etc/letsencrypt/live/subdomain.domain.com/fullchain.pem;
         ssl_certificate_key /etc/letsencrypt/live/subdomain.domain.com/privkey.pem;
         include /etc/letsencrypt/options-ssl-nginx.conf;
         ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

         location / {
             proxy_pass https://<auth0-tenant.xxx>.edge.tenants.auth0.com; # see https://auth0.com/docs/customize/custom-domains/self-managed-certificates#origin-hostname-settings
             include /etc/nginx/subdomain-files/common_proxy_headers.conf;
         }
     }

     server {
         listen 80;
         server_name subdomain.domain.com;
         return 301 https://$host$request_uri;
     }
     ```

4. **Configure NGINX for mTLS Domain** (`mtls.subdomain.domain.com`):
   - Create or edit the NGINX configuration file for your mTLS domain, typically located at `/etc/nginx/sites-available/mtls-subdomain`.
   - Use the following configuration:
     ```nginx
     server {
         listen 443 ssl;
         server_name mtls.subdomain.domain.com;

         # SSL/TLS certificates
         ssl_certificate /etc/letsencrypt/live/mtls.subdomain.domain.com/fullchain.pem;
         ssl_certificate_key /etc/letsencrypt/live/mtls.subdomain.domain.com/privkey.pem;
         include /etc/letsencrypt/options-ssl-nginx.conf;
         ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

         # Client-side SSL/TLS certificate settings
         ssl_client_certificate /etc/nginx/client_certs/subdomain.crt;
         ssl_verify_client optional_no_ca;
         ssl_verify_depth 2;

         location / {
             proxy_pass https://oidc-tests-cd-enrtxifleeouj0gn.edge.tenants.auth0.com;
             include /etc/nginx/subdomain-files/common_proxy_headers.conf;
             proxy_set_header Client-Certificate $ssl_client_escaped_cert;
             proxy_set_header Client-Certificate-CA-Verified $ssl_client_verify;
         }

         access_log /var/log/nginx/mtls.subdomain.domain.com-access.log;
         error_log /var/log/nginx/mtls.subdomain.domain.com-error.log debug;
     }

     server {
         listen 80;
         server_name mtls.subdomain.domain.com;
         return 301 https://$host$request_uri;
     }
     ```

   - Ensure that `/etc/nginx/subdomain-files/common_proxy_headers.conf` contains headers such as:
     ```nginx
     proxy_set_header cname-api-key "1be...26b";# cname api key provided as part of the setup in Auth0
     proxy_set_header X-Real-IP $remote_addr;
     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
     proxy_pass_header Set-Cookie;
     proxy_pass_header User-Agent;
     proxy_pass_header Origin;
     proxy_pass_header Referer;
     proxy_pass_header Authorization;
     proxy_pass_header Accept;
     proxy_pass_header Accept-Language;
     ```

5. **Enable and Test NGINX Configuration**:
   - Create symbolic links to enable your site configurations:
     ```bash
     sudo ln -s /etc/nginx/sites-available/subdomain /etc/nginx/sites-enabled/
     sudo ln -s /etc/nginx/sites-available/mtls-subdomain /etc/nginx/sites-enabled/
     ```
   - Test the NGINX configuration and reload NGINX:
     ```bash
     sudo nginx -t
     sudo systemctl reload nginx
     ```

#### 3. Configuring DNS ( either with A or AAAA records or CNAME)

1. **Create DNS Records**:
   - Log in to your DNS provider's management console.
   - Add A or AAAA records for `subdomain.domain.com` and `mtls.subdomain.domain.com` pointing to your server's IP address.

2. **Add CNAME Records for Auth0**:
    - Create a CNAME record if you prefer to alias your custom domains to another hostname that points to your NGINX server. This can be useful if you want to manage multiple domains that all point to the same NGINX setup without changing A/AAAA records.
   - After verifying the domain in Auth0, add CNAME records pointing to your NGINX proxy.
     - subdomain.domain.com -> proxy.yourdomain.com (where proxy.yourdomain.com is an A or AAAA record pointing to the NGINX server’s IP or just use the server IP address)
     - mtls.subdomain.domain.com -> proxy.yourdomain.com 

3. **Ensure DNS Propagation**:
   - Use tools like `dig` or online DNS checkers to verify that the DNS records have propagated correctly.

### Note

This setup allows you to use custom domains with self-managed certificates for Auth0 using NGINX. By configuring NGINX as a reverse proxy, you handle SSL/TLS termination and mTLS. 

For more detailed guidance and the latest information, refer to the [Auth0 documentation on custom domains](https://auth0.com/docs/customize/custom-domains/self-managed-certificates).