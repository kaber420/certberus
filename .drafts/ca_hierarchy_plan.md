# Multiple Intermediate CAs Support Plan

Enable the creation and management of multiple Intermediate CAs with custom security policies and validity periods directly from the Web Console.

## Proposed Changes

### Database Layer
#### [MODIFY] [models.py](file:///home/kaber420/Documentos/proyectos/certberus/certberus/db/models.py)
- Add a `Authority` model to track Intermediate CAs.
- Add `authority_id` to the `Certificate` model to track which CA signed each certificate.

### PKI Engine
#### [MODIFY] [pki.py](file:///home/kaber420/Documentos/proyectos/certberus/certberus/pki.py)
- Refactor `create_intermediate_ca` to accept a `name/slug` and store files in an `intermediates/` directory.
- Update `sign_certificate` and `sign_csr` to dynamically load the required Intermediate CA based on the requested profile or an explicit CA ID.

### Admin API
#### [MODIFY] [admin_api.py](file:///home/kaber420/Documentos/proyectos/certberus/certberus/integrations/admin_api.py)
- `GET /admin/cas`: List all active authorities.
- `POST /admin/cas/intermediate`: Create a new intermediate CA with custom Name Constraints and validity.
- Update `GET /admin/stats` to group by Authority.

### Web Console
#### [MODIFY] [index.html](file:///home/kaber420/Documentos/proyectos/certberus/certberus/static/index.html)
- Add "Jerarquía CA" (CA Hierarchy) to the sidebar.
- Create a new view for CA management.
#### [MODIFY] [app.js](file:///home/kaber420/Documentos/proyectos/certberus/certberus/static/app.js)
- Implement state management for multiple CAs.
- Create a wizard/modal for creating new Intermediate CAs.
- Update the certificates table to show which CA issued them.

## Verification Plan

### Automated Tests
- Create multiple CAs with different Name Constraints via API.
- Verify that certificates signed by "CA-IoT" are rejected for domains not in its constraint list.
- Verify that validity periods match the CA config.

### Manual Verification
- Use the Web GUI to create a "CA-Legacy" and an "CA-Cloud".
- Issue certificates from both and verify the chains.
