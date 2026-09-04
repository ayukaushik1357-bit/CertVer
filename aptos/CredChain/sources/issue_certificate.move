module CredChain::issue_certificate {
    use std::error;
    use std::signer;
    use std::string;
    use std::vector;
    use aptos_framework::event;

    /// Only registered issuers can issue certificates.
    struct IssuerRegistry has key {
        issuers: vector<address>,
    }

    struct CertificateHolder has key {
        certificates: vector<Certificate>,
    }

    struct Certificate has store {
        certificate_id: string::String,
        certificate_data: string::String,
        issuer: address,
    }

    #[event]
    struct CertificateIssued has drop, store {
        issuer: address,
        recipient: address,
        certificate_id: string::String,
        certificate_data: string::String,
    }

    #[event]
    struct IssuerAdded has drop, store {
        issuer: address,
    }

    const ENO_CERTIFICATE: u64 = 0;
    const ENOT_ADMIN: u64 = 1;
    const ENOT_AUTHORIZED_ISSUER: u64 = 2;
    const EDUPLICATE_CERTIFICATE_ID: u64 = 3;
    const EREGISTRY_ALREADY_INITIALIZED: u64 = 4;

    /// Module admin address — deploy account. Only this address can add/remove issuers.
    const ADMIN: address = @CredChain;

    /// Call once after deployment to set up the issuer registry.
    public entry fun init_registry(admin: &signer) {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == ADMIN, error::permission_denied(ENOT_ADMIN));
        assert!(!exists<IssuerRegistry>(admin_addr), error::already_exists(EREGISTRY_ALREADY_INITIALIZED));
        move_to(admin, IssuerRegistry { issuers: vector::empty<address>() });
    }

    /// Admin whitelists an institution/issuer address.
    public entry fun add_issuer(admin: &signer, issuer: address) acquires IssuerRegistry {
        let admin_addr = signer::address_of(admin);
        assert!(admin_addr == ADMIN, error::permission_denied(ENOT_ADMIN));
        let registry = borrow_global_mut<IssuerRegistry>(ADMIN);
        if (!vector::contains(&registry.issuers, &issuer)) {
            vector::push_back(&mut registry.issuers, issuer);
            event::emit(IssuerAdded { issuer });
        }
    }

    fun is_authorized_issuer(addr: address): bool acquires IssuerRegistry {
        if (!exists<IssuerRegistry>(ADMIN)) return false;
        let registry = borrow_global<IssuerRegistry>(ADMIN);
        vector::contains(&registry.issuers, &addr)
    }

    #[view]
    public fun get_certificate(addr: address, cert_id: string::String): string::String acquires CertificateHolder {
        assert!(exists<CertificateHolder>(addr), error::not_found(ENO_CERTIFICATE));
        let holder = borrow_global<CertificateHolder>(addr);
        let i = 0;
        let len = vector::length(&holder.certificates);
        while (i < len) {
            let cert = vector::borrow(&holder.certificates, i);
            if (cert.certificate_id == cert_id) {
                return cert.certificate_data
            };
            i = i + 1;
        };
        abort error::not_found(ENO_CERTIFICATE)
    }

    /// Only a whitelisted issuer can issue a certificate, and it can issue to ANY recipient
    /// (not just itself) — this is what "institution issues to student" actually requires.
    public entry fun issue_certificate(
        issuer: &signer,
        recipient: address,
        certificate_id: string::String,
        certificate_data: string::String
    ) acquires CertificateHolder, IssuerRegistry {
        let issuer_addr = signer::address_of(issuer);
        assert!(is_authorized_issuer(issuer_addr), error::permission_denied(ENOT_AUTHORIZED_ISSUER));

        if (!exists<CertificateHolder>(recipient)) {
            let certificates = vector::empty<Certificate>();
            vector::push_back(&mut certificates, Certificate {
                certificate_id,
                certificate_data,
                issuer: issuer_addr,
            });
            move_to(issuer, CertificateHolder { certificates });
        } else {
            let holder = borrow_global_mut<CertificateHolder>(recipient);
            let i = 0;
            let len = vector::length(&holder.certificates);
            while (i < len) {
                let existing = vector::borrow(&holder.certificates, i);
                assert!(existing.certificate_id != certificate_id, error::already_exists(EDUPLICATE_CERTIFICATE_ID));
                i = i + 1;
            };
            vector::push_back(&mut holder.certificates, Certificate {
                certificate_id,
                certificate_data,
                issuer: issuer_addr,
            });
        };

        event::emit(CertificateIssued {
            issuer: issuer_addr,
            recipient,
            certificate_id,
            certificate_data,
        });
    }

    #[test(admin = @CredChain, issuer = @0x2, recipient = @0x3)]
    public entry fun test_issue_and_get_certificate(admin: signer, issuer: signer, recipient: signer) acquires CertificateHolder, IssuerRegistry {
        let issuer_addr = signer::address_of(&issuer);
        let recipient_addr = signer::address_of(&recipient);
        aptos_framework::account::create_account_for_test(signer::address_of(&admin));
        aptos_framework::account::create_account_for_test(issuer_addr);
        aptos_framework::account::create_account_for_test(recipient_addr);

        init_registry(&admin);
        add_issuer(&admin, issuer_addr);

        issue_certificate(&issuer, recipient_addr, string::utf8(b"cert1"), string::utf8(b"Certificate Data"));

        assert!(
            get_certificate(recipient_addr, string::utf8(b"cert1")) == string::utf8(b"Certificate Data"),
            ENO_CERTIFICATE
        );
    }

    #[test(admin = @CredChain, fake_issuer = @0x4, recipient = @0x3)]
    #[expected_failure(abort_code = 0x50002, location = Self)]
    public entry fun test_unauthorized_issuer_fails(admin: signer, fake_issuer: signer, recipient: signer) acquires CertificateHolder, IssuerRegistry {
        aptos_framework::account::create_account_for_test(signer::address_of(&admin));
        aptos_framework::account::create_account_for_test(signer::address_of(&fake_issuer));
        aptos_framework::account::create_account_for_test(signer::address_of(&recipient));

        init_registry(&admin);
        // fake_issuer was never added via add_issuer — this must fail
        issue_certificate(&fake_issuer, signer::address_of(&recipient), string::utf8(b"cert1"), string::utf8(b"Data"));
    }
}