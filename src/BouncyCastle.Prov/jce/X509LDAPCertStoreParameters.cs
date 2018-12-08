namespace org.bouncycastle.jce
{
	using X509StoreParameters = org.bouncycastle.x509.X509StoreParameters;


	/// <summary>
	/// An expanded set of parameters for an LDAPCertStore
	/// </summary>
	public class X509LDAPCertStoreParameters : X509StoreParameters, CertStoreParameters
	{

		private string ldapURL;

		private string baseDN;

		// LDAP attributes, where data is stored

		private string userCertificateAttribute;

		private string cACertificateAttribute;

		private string crossCertificateAttribute;

		private string certificateRevocationListAttribute;

		private string deltaRevocationListAttribute;

		private string authorityRevocationListAttribute;

		private string attributeCertificateAttributeAttribute;

		private string aACertificateAttribute;

		private string attributeDescriptorCertificateAttribute;

		private string attributeCertificateRevocationListAttribute;

		private string attributeAuthorityRevocationListAttribute;

		// LDAP attributes with which data can be found

		private string ldapUserCertificateAttributeName;

		private string ldapCACertificateAttributeName;

		private string ldapCrossCertificateAttributeName;

		private string ldapCertificateRevocationListAttributeName;

		private string ldapDeltaRevocationListAttributeName;

		private string ldapAuthorityRevocationListAttributeName;

		private string ldapAttributeCertificateAttributeAttributeName;

		private string ldapAACertificateAttributeName;

		private string ldapAttributeDescriptorCertificateAttributeName;

		private string ldapAttributeCertificateRevocationListAttributeName;

		private string ldapAttributeAuthorityRevocationListAttributeName;

		// certificates and CRLs subject or issuer DN attributes, which must be
		// matched against ldap attribute names

		private string userCertificateSubjectAttributeName;

		private string cACertificateSubjectAttributeName;

		private string crossCertificateSubjectAttributeName;

		private string certificateRevocationListIssuerAttributeName;

		private string deltaRevocationListIssuerAttributeName;

		private string authorityRevocationListIssuerAttributeName;

		private string attributeCertificateAttributeSubjectAttributeName;

		private string aACertificateSubjectAttributeName;

		private string attributeDescriptorCertificateSubjectAttributeName;

		private string attributeCertificateRevocationListIssuerAttributeName;

		private string attributeAuthorityRevocationListIssuerAttributeName;

		private string searchForSerialNumberIn;

		public class Builder
		{
			internal string ldapURL;

			internal string baseDN;

			// LDAP attributes, where data is stored

			internal string userCertificateAttribute;

			internal string cACertificateAttribute;

			internal string crossCertificateAttribute;

			internal string certificateRevocationListAttribute;

			internal string deltaRevocationListAttribute;

			internal string authorityRevocationListAttribute;

			internal string attributeCertificateAttributeAttribute;

			internal string aACertificateAttribute;

			internal string attributeDescriptorCertificateAttribute;

			internal string attributeCertificateRevocationListAttribute;

			internal string attributeAuthorityRevocationListAttribute;

			// LDAP attributes with which data can be found

			internal string ldapUserCertificateAttributeName;

			internal string ldapCACertificateAttributeName;

			internal string ldapCrossCertificateAttributeName;

			internal string ldapCertificateRevocationListAttributeName;

			internal string ldapDeltaRevocationListAttributeName;

			internal string ldapAuthorityRevocationListAttributeName;

			internal string ldapAttributeCertificateAttributeAttributeName;

			internal string ldapAACertificateAttributeName;

			internal string ldapAttributeDescriptorCertificateAttributeName;

			internal string ldapAttributeCertificateRevocationListAttributeName;

			internal string ldapAttributeAuthorityRevocationListAttributeName;

			// certificates and CRLs subject or issuer DN attributes, which must be
			// matched against ldap attribute names

			internal string userCertificateSubjectAttributeName;

			internal string cACertificateSubjectAttributeName;

			internal string crossCertificateSubjectAttributeName;

			internal string certificateRevocationListIssuerAttributeName;

			internal string deltaRevocationListIssuerAttributeName;

			internal string authorityRevocationListIssuerAttributeName;

			internal string attributeCertificateAttributeSubjectAttributeName;

			internal string aACertificateSubjectAttributeName;

			internal string attributeDescriptorCertificateSubjectAttributeName;

			internal string attributeCertificateRevocationListIssuerAttributeName;

			internal string attributeAuthorityRevocationListIssuerAttributeName;

			internal string searchForSerialNumberIn;

			public Builder() : this("ldap://localhost:389", "")
			{
			}

			public Builder(string ldapURL, string baseDN)
			{
				this.ldapURL = ldapURL;
				if (string.ReferenceEquals(baseDN, null))
				{
					this.baseDN = "";
				}
				else
				{
					this.baseDN = baseDN;
				}

				this.userCertificateAttribute = "userCertificate";
				this.cACertificateAttribute = "cACertificate";
				this.crossCertificateAttribute = "crossCertificatePair";
				this.certificateRevocationListAttribute = "certificateRevocationList";
				this.deltaRevocationListAttribute = "deltaRevocationList";
				this.authorityRevocationListAttribute = "authorityRevocationList";
				this.attributeCertificateAttributeAttribute = "attributeCertificateAttribute";
				this.aACertificateAttribute = "aACertificate";
				this.attributeDescriptorCertificateAttribute = "attributeDescriptorCertificate";
				this.attributeCertificateRevocationListAttribute = "attributeCertificateRevocationList";
				this.attributeAuthorityRevocationListAttribute = "attributeAuthorityRevocationList";
				this.ldapUserCertificateAttributeName = "cn";
				this.ldapCACertificateAttributeName = "cn ou o";
				this.ldapCrossCertificateAttributeName = "cn ou o";
				this.ldapCertificateRevocationListAttributeName = "cn ou o";
				this.ldapDeltaRevocationListAttributeName = "cn ou o";
				this.ldapAuthorityRevocationListAttributeName = "cn ou o";
				this.ldapAttributeCertificateAttributeAttributeName = "cn";
				this.ldapAACertificateAttributeName = "cn o ou";
				this.ldapAttributeDescriptorCertificateAttributeName = "cn o ou";
				this.ldapAttributeCertificateRevocationListAttributeName = "cn o ou";
				this.ldapAttributeAuthorityRevocationListAttributeName = "cn o ou";
				this.userCertificateSubjectAttributeName = "cn";
				this.cACertificateSubjectAttributeName = "o ou";
				this.crossCertificateSubjectAttributeName = "o ou";
				this.certificateRevocationListIssuerAttributeName = "o ou";
				this.deltaRevocationListIssuerAttributeName = "o ou";
				this.authorityRevocationListIssuerAttributeName = "o ou";
				this.attributeCertificateAttributeSubjectAttributeName = "cn";
				this.aACertificateSubjectAttributeName = "o ou";
				this.attributeDescriptorCertificateSubjectAttributeName = "o ou";
				this.attributeCertificateRevocationListIssuerAttributeName = "o ou";
				this.attributeAuthorityRevocationListIssuerAttributeName = "o ou";
				this.searchForSerialNumberIn = "uid serialNumber cn";
			}

			/// <param name="userCertificateAttribute">       Attribute name(s) in the LDAP directory where end certificates
			///                                       are stored. Separated by space. Defaults to "userCertificate"
			///                                       if <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setUserCertificateAttribute(string userCertificateAttribute)
			{
				this.userCertificateAttribute = userCertificateAttribute;

				return this;
			}

			/// <param name="cACertificateAttribute">         Attribute name(s) in the LDAP directory where CA certificates
			///                                       are stored. Separated by space. Defaults to "cACertificate" if
			///                                       <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setCACertificateAttribute(string cACertificateAttribute)
			{
				this.cACertificateAttribute = cACertificateAttribute;

				return this;
			}

			/// <param name="crossCertificateAttribute">      Attribute name(s), where the cross certificates are stored.
			///                                       Separated by space. Defaults to "crossCertificatePair" if
			///                                       <code>null</code> </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setCrossCertificateAttribute(string crossCertificateAttribute)
			{
				this.crossCertificateAttribute = crossCertificateAttribute;

				return this;
			}

			/// <param name="certificateRevocationListAttribute">
			///                                       Attribute name(s) in the LDAP directory where CRLs are stored.
			///                                       Separated by space. Defaults to "certificateRevocationList" if
			///                                       <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setCertificateRevocationListAttribute(string certificateRevocationListAttribute)
			{
				this.certificateRevocationListAttribute = certificateRevocationListAttribute;

				return this;
			}

			/// <param name="deltaRevocationListAttribute">   Attribute name(s) in the LDAP directory where delta RLs are
			///                                       stored. Separated by space. Defaults to "deltaRevocationList"
			///                                       if <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setDeltaRevocationListAttribute(string deltaRevocationListAttribute)
			{
				this.deltaRevocationListAttribute = deltaRevocationListAttribute;

				return this;
			}

			/// <param name="authorityRevocationListAttribute">
			///                                       Attribute name(s) in the LDAP directory where CRLs for
			///                                       authorities are stored. Separated by space. Defaults to
			///                                       "authorityRevocationList" if <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAuthorityRevocationListAttribute(string authorityRevocationListAttribute)
			{
				this.authorityRevocationListAttribute = authorityRevocationListAttribute;

				return this;
			}

			/// <param name="attributeCertificateAttributeAttribute">
			///                                       Attribute name(s) in the LDAP directory where end attribute
			///                                       certificates are stored. Separated by space. Defaults to
			///                                       "attributeCertificateAttribute" if <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAttributeCertificateAttributeAttribute(string attributeCertificateAttributeAttribute)
			{
				this.attributeCertificateAttributeAttribute = attributeCertificateAttributeAttribute;

				return this;
			}

			/// <param name="aACertificateAttribute">         Attribute name(s) in the LDAP directory where attribute
			///                                       certificates for attribute authorities are stored. Separated
			///                                       by space. Defaults to "aACertificate" if <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAACertificateAttribute(string aACertificateAttribute)
			{
				this.aACertificateAttribute = aACertificateAttribute;

				return this;
			}

			/// <param name="attributeDescriptorCertificateAttribute">
			///                                       Attribute name(s) in the LDAP directory where self signed
			///                                       attribute certificates for attribute authorities are stored.
			///                                       Separated by space. Defaults to
			///                                       "attributeDescriptorCertificate" if <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAttributeDescriptorCertificateAttribute(string attributeDescriptorCertificateAttribute)
			{
				this.attributeDescriptorCertificateAttribute = attributeDescriptorCertificateAttribute;

				return this;
			}

			/// <param name="attributeCertificateRevocationListAttribute">
			///                                       Attribute name(s) in the LDAP directory where CRLs for
			///                                       attribute certificates are stored. Separated by space.
			///                                       Defaults to "attributeCertificateRevocationList" if
			///                                       <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAttributeCertificateRevocationListAttribute(string attributeCertificateRevocationListAttribute)
			{
				this.attributeCertificateRevocationListAttribute = attributeCertificateRevocationListAttribute;

				return this;
			}

			/// <param name="attributeAuthorityRevocationListAttribute">
			///                                       Attribute name(s) in the LDAP directory where RLs for
			///                                       attribute authority attribute certificates are stored.
			///                                       Separated by space. Defaults to
			///                                       "attributeAuthorityRevocationList" if <code>null</code>. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAttributeAuthorityRevocationListAttribute(string attributeAuthorityRevocationListAttribute)
			{
				this.attributeAuthorityRevocationListAttribute = attributeAuthorityRevocationListAttribute;

				return this;
			}

			/// <param name="ldapUserCertificateAttributeName">
			///                                       The attribute name(s) in the LDAP directory where to search
			///                                       for the attribute value of the specified
			///                                       <code>userCertificateSubjectAttributeName</code>. E.g. if
			///                                       "cn" is used to put information about the subject for end
			///                                       certificates, then specify "cn". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapUserCertificateAttributeName(string ldapUserCertificateAttributeName)
			{
				this.ldapUserCertificateAttributeName = ldapUserCertificateAttributeName;

				return this;
			}

			/// <param name="ldapCACertificateAttributeName"> The attribute name(s) in the LDAP directory where to search
			///                                       for the attribute value of the specified
			///                                       <code>cACertificateSubjectAttributeName</code>. E.g. if
			///                                       "ou" is used to put information about the subject for CA
			///                                       certificates, then specify "ou". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapCACertificateAttributeName(string ldapCACertificateAttributeName)
			{
				this.ldapCACertificateAttributeName = ldapCACertificateAttributeName;

				return this;
			}

			/// <param name="ldapCrossCertificateAttributeName">
			///                                       The attribute name(s) in the LDAP directory where to search for
			///                                       the attribute value of the specified
			///                                       <code>crossCertificateSubjectAttributeName</code>. E.g. if
			///                                       "o" is used to put information about the subject for cross
			///                                       certificates, then specify "o". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapCrossCertificateAttributeName(string ldapCrossCertificateAttributeName)
			{
				this.ldapCrossCertificateAttributeName = ldapCrossCertificateAttributeName;

				return this;
			}

			/// <param name="ldapCertificateRevocationListAttributeName">
			///                                       The attribute name(s) in the LDAP directory where to search for
			///                                       the attribute value of the specified
			///                                       <code>certificateRevocationListIssuerAttributeName</code>.
			///                                       E.g. if "ou" is used to put information about the issuer of
			///                                       CRLs, specify "ou". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapCertificateRevocationListAttributeName(string ldapCertificateRevocationListAttributeName)
			{
				this.ldapCertificateRevocationListAttributeName = ldapCertificateRevocationListAttributeName;

				return this;
			}

			/// <param name="ldapDeltaRevocationListAttributeName">
			///                                       The attribute name(s) in the LDAP directory where to search for
			///                                       the attribute value of the specified
			///                                       <code>deltaRevocationListIssuerAttributeName</code>. E.g.
			///                                       if "ou" is used to put information about the issuer of CRLs,
			///                                       specify "ou". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapDeltaRevocationListAttributeName(string ldapDeltaRevocationListAttributeName)
			{
				this.ldapDeltaRevocationListAttributeName = ldapDeltaRevocationListAttributeName;

				return this;
			}

			/// <param name="ldapAuthorityRevocationListAttributeName">
			///                                       The attribute name(s) in the LDAP directory where to search for
			///                                       the attribute value of the specified
			///                                       <code>authorityRevocationListIssuerAttributeName</code>.
			///                                       E.g. if "ou" is used to put information about the issuer of
			///                                       CRLs, specify "ou". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapAuthorityRevocationListAttributeName(string ldapAuthorityRevocationListAttributeName)
			{
				this.ldapAuthorityRevocationListAttributeName = ldapAuthorityRevocationListAttributeName;

				return this;
			}

			/// <param name="ldapAttributeCertificateAttributeAttributeName">
			///                                       The attribute name(s) in the LDAP directory where to search for
			///                                       the attribute value of the specified
			///                                       <code>attributeCertificateAttributeSubjectAttributeName</code>.
			///                                       E.g. if "cn" is used to put information about the subject of
			///                                       end attribute certificates, specify "cn". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapAttributeCertificateAttributeAttributeName(string ldapAttributeCertificateAttributeAttributeName)
			{
				this.ldapAttributeCertificateAttributeAttributeName = ldapAttributeCertificateAttributeAttributeName;

				return this;
			}

			/// <param name="ldapAACertificateAttributeName"> The attribute name(s) in the LDAP directory where to search for
			///                                       the attribute value of the specified
			///                                       <code>aACertificateSubjectAttributeName</code>. E.g. if
			///                                       "ou" is used to put information about the subject of attribute
			///                                       authority attribute certificates, specify "ou". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapAACertificateAttributeName(string ldapAACertificateAttributeName)
			{
				this.ldapAACertificateAttributeName = ldapAACertificateAttributeName;

				return this;
			}

			/// <param name="ldapAttributeDescriptorCertificateAttributeName">
			///                                       The attribute name(s) in the LDAP directory where to search for
			///                                       the attribute value of the specified
			///                                       <code>attributeDescriptorCertificateSubjectAttributeName</code>.
			///                                       E.g. if "o" is used to put information about the subject of
			///                                       self signed attribute authority attribute certificates,
			///                                       specify "o". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapAttributeDescriptorCertificateAttributeName(string ldapAttributeDescriptorCertificateAttributeName)
			{
				this.ldapAttributeDescriptorCertificateAttributeName = ldapAttributeDescriptorCertificateAttributeName;

				return this;
			}

			/// <param name="ldapAttributeCertificateRevocationListAttributeName">
			///                                       The attribute name(s) in the LDAP directory where to search for
			///                                       the attribute value of the specified
			///                                       <code>attributeCertificateRevocationListIssuerAttributeName</code>.
			///                                       E.g. if "ou" is used to put information about the issuer of
			///                                       CRLs, specify "ou". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapAttributeCertificateRevocationListAttributeName(string ldapAttributeCertificateRevocationListAttributeName)
			{
				this.ldapAttributeCertificateRevocationListAttributeName = ldapAttributeCertificateRevocationListAttributeName;

				return this;
			}

			/// <param name="ldapAttributeAuthorityRevocationListAttributeName">
			///                                       The attribute name(s) in the LDAP directory where to search for
			///                                       the attribute value of the specified
			///                                       <code>attributeAuthorityRevocationListIssuerAttributeName</code>.
			///                                       E.g. if "ou" is used to put information about the issuer of
			///                                       CRLs, specify "ou". </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setLdapAttributeAuthorityRevocationListAttributeName(string ldapAttributeAuthorityRevocationListAttributeName)
			{
				this.ldapAttributeAuthorityRevocationListAttributeName = ldapAttributeAuthorityRevocationListAttributeName;

				return this;
			}

			/// <param name="userCertificateSubjectAttributeName">
			///                                       Attribute(s) in the subject of the certificate which is used
			///                                       to be searched in the
			///                                       <code>ldapUserCertificateAttributeName</code>. E.g. the
			///                                       "cn" attribute of the DN could be used. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setUserCertificateSubjectAttributeName(string userCertificateSubjectAttributeName)
			{
				this.userCertificateSubjectAttributeName = userCertificateSubjectAttributeName;

				return this;
			}

			/// <param name="cACertificateSubjectAttributeName">
			///                                       Attribute(s) in the subject of the certificate which is used
			///                                       to be searched in the
			///                                       <code>ldapCACertificateAttributeName</code>. E.g. the "ou"
			///                                       attribute of the DN could be used. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setCACertificateSubjectAttributeName(string cACertificateSubjectAttributeName)
			{
				this.cACertificateSubjectAttributeName = cACertificateSubjectAttributeName;

				return this;
			}

			/// <param name="crossCertificateSubjectAttributeName">
			///                                       Attribute(s) in the subject of the cross certificate which is
			///                                       used to be searched in the
			///                                       <code>ldapCrossCertificateAttributeName</code>. E.g. the
			///                                       "o" attribute of the DN may be appropriate. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setCrossCertificateSubjectAttributeName(string crossCertificateSubjectAttributeName)
			{
				this.crossCertificateSubjectAttributeName = crossCertificateSubjectAttributeName;

				return this;
			}

			/// <param name="certificateRevocationListIssuerAttributeName">
			///                                       Attribute(s) in the issuer of the CRL which is used to be
			///                                       searched in the
			///                                       <code>ldapCertificateRevocationListAttributeName</code>.
			///                                       E.g. the "o" or "ou" attribute may be used. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setCertificateRevocationListIssuerAttributeName(string certificateRevocationListIssuerAttributeName)
			{
				this.certificateRevocationListIssuerAttributeName = certificateRevocationListIssuerAttributeName;

				return this;
			}

			/// <param name="deltaRevocationListIssuerAttributeName">
			///                                       Attribute(s) in the issuer of the CRL which is used to be
			///                                       searched in the
			///                                       <code>ldapDeltaRevocationListAttributeName</code>. E.g. the
			///                                       "o" or "ou" attribute may be used. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setDeltaRevocationListIssuerAttributeName(string deltaRevocationListIssuerAttributeName)
			{
				this.deltaRevocationListIssuerAttributeName = deltaRevocationListIssuerAttributeName;

				return this;
			}

			/// <param name="authorityRevocationListIssuerAttributeName">
			///                                       Attribute(s) in the issuer of the CRL which is used to be
			///                                       searched in the
			///                                       <code>ldapAuthorityRevocationListAttributeName</code>. E.g.
			///                                       the "o" or "ou" attribute may be used. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAuthorityRevocationListIssuerAttributeName(string authorityRevocationListIssuerAttributeName)
			{
				this.authorityRevocationListIssuerAttributeName = authorityRevocationListIssuerAttributeName;

				return this;
			}

			/// <param name="attributeCertificateAttributeSubjectAttributeName">
			///                                       Attribute(s) in the subject of the attribute certificate which
			///                                       is used to be searched in the
			///                                       <code>ldapAttributeCertificateAttributeAttributeName</code>.
			///                                       E.g. the "cn" attribute of the DN could be used. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAttributeCertificateAttributeSubjectAttributeName(string attributeCertificateAttributeSubjectAttributeName)
			{
				this.attributeCertificateAttributeSubjectAttributeName = attributeCertificateAttributeSubjectAttributeName;

				return this;
			}

			/// <param name="aACertificateSubjectAttributeName">
			///                                       Attribute(s) in the subject of the attribute certificate which
			///                                       is used to be searched in the
			///                                       <code>ldapAACertificateAttributeName</code>. E.g. the "ou"
			///                                       attribute of the DN could be used. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAACertificateSubjectAttributeName(string aACertificateSubjectAttributeName)
			{
				this.aACertificateSubjectAttributeName = aACertificateSubjectAttributeName;

				return this;
			}

			/// <param name="attributeDescriptorCertificateSubjectAttributeName">
			///                                       Attribute(s) in the subject of the attribute certificate which
			///                                       is used to be searched in the
			///                                       <code>ldapAttributeDescriptorCertificateAttributeName</code>.
			///                                       E.g. the "o" attribute of the DN could be used. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAttributeDescriptorCertificateSubjectAttributeName(string attributeDescriptorCertificateSubjectAttributeName)
			{
				this.attributeDescriptorCertificateSubjectAttributeName = attributeDescriptorCertificateSubjectAttributeName;

				return this;
			}

			/// <param name="attributeCertificateRevocationListIssuerAttributeName">
			///                                       Attribute(s) in the issuer of the CRL which is used to be
			///                                       searched in the
			///                                       <code>ldapAttributeCertificateRevocationListAttributeName</code>.
			///                                       E.g. the "o" or "ou" attribute may be used
			///                                       certificate is searched in this LDAP attribute. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAttributeCertificateRevocationListIssuerAttributeName(string attributeCertificateRevocationListIssuerAttributeName)
			{
				this.attributeCertificateRevocationListIssuerAttributeName = attributeCertificateRevocationListIssuerAttributeName;

				return this;
			}

			/// <param name="attributeAuthorityRevocationListIssuerAttributeName">
			///                                       Anttribute(s) in the issuer of the CRL which is used to be
			///                                       searched in the
			///                                       <code>ldapAttributeAuthorityRevocationListAttributeName</code>.
			///                                       E.g. the "o" or "ou" attribute may be used. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setAttributeAuthorityRevocationListIssuerAttributeName(string attributeAuthorityRevocationListIssuerAttributeName)
			{
				this.attributeAuthorityRevocationListIssuerAttributeName = attributeAuthorityRevocationListIssuerAttributeName;

				return this;
			}

			/// 
			/// <param name="searchForSerialNumberIn">        If not <code>null</code> the serial number of the
			///                                       certificate is searched in this LDAP attribute. </param>
			/// <exception cref="IllegalArgumentException"> if a necessary parameter is <code>null</code>. </exception>
			/// <returns> the builder </returns>
			public virtual Builder setSearchForSerialNumberIn(string searchForSerialNumberIn)
			{
				this.searchForSerialNumberIn = searchForSerialNumberIn;

				return this;
			}

			public virtual X509LDAPCertStoreParameters build()
			{
				 if (string.ReferenceEquals(ldapUserCertificateAttributeName, null) || string.ReferenceEquals(ldapCACertificateAttributeName, null) || string.ReferenceEquals(ldapCrossCertificateAttributeName, null) || string.ReferenceEquals(ldapCertificateRevocationListAttributeName, null) || string.ReferenceEquals(ldapDeltaRevocationListAttributeName, null) || string.ReferenceEquals(ldapAuthorityRevocationListAttributeName, null) || string.ReferenceEquals(ldapAttributeCertificateAttributeAttributeName, null) || string.ReferenceEquals(ldapAACertificateAttributeName, null) || string.ReferenceEquals(ldapAttributeDescriptorCertificateAttributeName, null) || string.ReferenceEquals(ldapAttributeCertificateRevocationListAttributeName, null) || string.ReferenceEquals(ldapAttributeAuthorityRevocationListAttributeName, null) || string.ReferenceEquals(userCertificateSubjectAttributeName, null) || string.ReferenceEquals(cACertificateSubjectAttributeName, null) || string.ReferenceEquals(crossCertificateSubjectAttributeName, null) || string.ReferenceEquals(certificateRevocationListIssuerAttributeName, null) || string.ReferenceEquals(deltaRevocationListIssuerAttributeName, null) || string.ReferenceEquals(authorityRevocationListIssuerAttributeName, null) || string.ReferenceEquals(attributeCertificateAttributeSubjectAttributeName, null) || string.ReferenceEquals(aACertificateSubjectAttributeName, null) || string.ReferenceEquals(attributeDescriptorCertificateSubjectAttributeName, null) || string.ReferenceEquals(attributeCertificateRevocationListIssuerAttributeName, null) || string.ReferenceEquals(attributeAuthorityRevocationListIssuerAttributeName, null))
				 {
					throw new IllegalArgumentException("Necessary parameters not specified.");
				 }
				return new X509LDAPCertStoreParameters(this);
			}
		}


		private X509LDAPCertStoreParameters(Builder builder)
		{
			this.ldapURL = builder.ldapURL;
			this.baseDN = builder.baseDN;

			this.userCertificateAttribute = builder.userCertificateAttribute;
			this.cACertificateAttribute = builder.cACertificateAttribute;
			this.crossCertificateAttribute = builder.crossCertificateAttribute;
			this.certificateRevocationListAttribute = builder.certificateRevocationListAttribute;
			this.deltaRevocationListAttribute = builder.deltaRevocationListAttribute;
			this.authorityRevocationListAttribute = builder.authorityRevocationListAttribute;
			this.attributeCertificateAttributeAttribute = builder.attributeCertificateAttributeAttribute;
			this.aACertificateAttribute = builder.aACertificateAttribute;
			this.attributeDescriptorCertificateAttribute = builder.attributeDescriptorCertificateAttribute;
			this.attributeCertificateRevocationListAttribute = builder.attributeCertificateRevocationListAttribute;
			this.attributeAuthorityRevocationListAttribute = builder.attributeAuthorityRevocationListAttribute;
			this.ldapUserCertificateAttributeName = builder.ldapUserCertificateAttributeName;
			this.ldapCACertificateAttributeName = builder.ldapCACertificateAttributeName;
			this.ldapCrossCertificateAttributeName = builder.ldapCrossCertificateAttributeName;
			this.ldapCertificateRevocationListAttributeName = builder.ldapCertificateRevocationListAttributeName;
			this.ldapDeltaRevocationListAttributeName = builder.ldapDeltaRevocationListAttributeName;
			this.ldapAuthorityRevocationListAttributeName = builder.ldapAuthorityRevocationListAttributeName;
			this.ldapAttributeCertificateAttributeAttributeName = builder.ldapAttributeCertificateAttributeAttributeName;
			this.ldapAACertificateAttributeName = builder.ldapAACertificateAttributeName;
			this.ldapAttributeDescriptorCertificateAttributeName = builder.ldapAttributeDescriptorCertificateAttributeName;
			this.ldapAttributeCertificateRevocationListAttributeName = builder.ldapAttributeCertificateRevocationListAttributeName;
			this.ldapAttributeAuthorityRevocationListAttributeName = builder.ldapAttributeAuthorityRevocationListAttributeName;
			this.userCertificateSubjectAttributeName = builder.userCertificateSubjectAttributeName;
			this.cACertificateSubjectAttributeName = builder.cACertificateSubjectAttributeName;
			this.crossCertificateSubjectAttributeName = builder.crossCertificateSubjectAttributeName;
			this.certificateRevocationListIssuerAttributeName = builder.certificateRevocationListIssuerAttributeName;
			this.deltaRevocationListIssuerAttributeName = builder.deltaRevocationListIssuerAttributeName;
			this.authorityRevocationListIssuerAttributeName = builder.authorityRevocationListIssuerAttributeName;
			this.attributeCertificateAttributeSubjectAttributeName = builder.attributeCertificateAttributeSubjectAttributeName;
			this.aACertificateSubjectAttributeName = builder.aACertificateSubjectAttributeName;
			this.attributeDescriptorCertificateSubjectAttributeName = builder.attributeDescriptorCertificateSubjectAttributeName;
			this.attributeCertificateRevocationListIssuerAttributeName = builder.attributeCertificateRevocationListIssuerAttributeName;
			this.attributeAuthorityRevocationListIssuerAttributeName = builder.attributeAuthorityRevocationListIssuerAttributeName;
			this.searchForSerialNumberIn = builder.searchForSerialNumberIn;
		}

		/// <summary>
		/// Returns a clone of this object.
		/// </summary>
		public virtual object clone()
		{
			return this;
		}

		public virtual bool equal(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is X509LDAPCertStoreParameters))
			{
				return false;
			}

			X509LDAPCertStoreParameters @params = (X509LDAPCertStoreParameters)o;
			return checkField(ldapURL, @params.ldapURL) && checkField(baseDN, @params.baseDN) && checkField(userCertificateAttribute, @params.userCertificateAttribute) && checkField(cACertificateAttribute, @params.cACertificateAttribute) && checkField(crossCertificateAttribute, @params.crossCertificateAttribute) && checkField(certificateRevocationListAttribute, @params.certificateRevocationListAttribute) && checkField(deltaRevocationListAttribute, @params.deltaRevocationListAttribute) && checkField(authorityRevocationListAttribute, @params.authorityRevocationListAttribute) && checkField(attributeCertificateAttributeAttribute, @params.attributeCertificateAttributeAttribute) && checkField(aACertificateAttribute, @params.aACertificateAttribute) && checkField(attributeDescriptorCertificateAttribute, @params.attributeDescriptorCertificateAttribute) && checkField(attributeCertificateRevocationListAttribute, @params.attributeCertificateRevocationListAttribute) && checkField(attributeAuthorityRevocationListAttribute, @params.attributeAuthorityRevocationListAttribute) && checkField(ldapUserCertificateAttributeName, @params.ldapUserCertificateAttributeName) && checkField(ldapCACertificateAttributeName, @params.ldapCACertificateAttributeName) && checkField(ldapCrossCertificateAttributeName, @params.ldapCrossCertificateAttributeName) && checkField(ldapCertificateRevocationListAttributeName, @params.ldapCertificateRevocationListAttributeName) && checkField(ldapDeltaRevocationListAttributeName, @params.ldapDeltaRevocationListAttributeName) && checkField(ldapAuthorityRevocationListAttributeName, @params.ldapAuthorityRevocationListAttributeName) && checkField(ldapAttributeCertificateAttributeAttributeName, @params.ldapAttributeCertificateAttributeAttributeName) && checkField(ldapAACertificateAttributeName, @params.ldapAACertificateAttributeName) && checkField(ldapAttributeDescriptorCertificateAttributeName, @params.ldapAttributeDescriptorCertificateAttributeName) && checkField(ldapAttributeCertificateRevocationListAttributeName, @params.ldapAttributeCertificateRevocationListAttributeName) && checkField(ldapAttributeAuthorityRevocationListAttributeName, @params.ldapAttributeAuthorityRevocationListAttributeName) && checkField(userCertificateSubjectAttributeName, @params.userCertificateSubjectAttributeName) && checkField(cACertificateSubjectAttributeName, @params.cACertificateSubjectAttributeName) && checkField(crossCertificateSubjectAttributeName, @params.crossCertificateSubjectAttributeName) && checkField(certificateRevocationListIssuerAttributeName, @params.certificateRevocationListIssuerAttributeName) && checkField(deltaRevocationListIssuerAttributeName, @params.deltaRevocationListIssuerAttributeName) && checkField(authorityRevocationListIssuerAttributeName, @params.authorityRevocationListIssuerAttributeName) && checkField(attributeCertificateAttributeSubjectAttributeName, @params.attributeCertificateAttributeSubjectAttributeName) && checkField(aACertificateSubjectAttributeName, @params.aACertificateSubjectAttributeName) && checkField(attributeDescriptorCertificateSubjectAttributeName, @params.attributeDescriptorCertificateSubjectAttributeName) && checkField(attributeCertificateRevocationListIssuerAttributeName, @params.attributeCertificateRevocationListIssuerAttributeName) && checkField(attributeAuthorityRevocationListIssuerAttributeName, @params.attributeAuthorityRevocationListIssuerAttributeName) && checkField(searchForSerialNumberIn, @params.searchForSerialNumberIn);
		}

		private bool checkField(object o1, object o2)
		{
			if (o1 == o2)
			{
				return true;
			}

			if (o1 == null)
			{
				return false;
			}

			return o1.Equals(o2);
		}

		public override int GetHashCode()
		{
			int hash = 0;

			hash = addHashCode(hash, userCertificateAttribute);
			hash = addHashCode(hash, cACertificateAttribute);
			hash = addHashCode(hash, crossCertificateAttribute);
			hash = addHashCode(hash, certificateRevocationListAttribute);
			hash = addHashCode(hash, deltaRevocationListAttribute);
			hash = addHashCode(hash, authorityRevocationListAttribute);
			hash = addHashCode(hash, attributeCertificateAttributeAttribute);
			hash = addHashCode(hash, aACertificateAttribute);
			hash = addHashCode(hash, attributeDescriptorCertificateAttribute);
			hash = addHashCode(hash, attributeCertificateRevocationListAttribute);
			hash = addHashCode(hash, attributeAuthorityRevocationListAttribute);
			hash = addHashCode(hash, ldapUserCertificateAttributeName);
			hash = addHashCode(hash, ldapCACertificateAttributeName);
			hash = addHashCode(hash, ldapCrossCertificateAttributeName);
			hash = addHashCode(hash, ldapCertificateRevocationListAttributeName);
			hash = addHashCode(hash, ldapDeltaRevocationListAttributeName);
			hash = addHashCode(hash, ldapAuthorityRevocationListAttributeName);
			hash = addHashCode(hash, ldapAttributeCertificateAttributeAttributeName);
			hash = addHashCode(hash, ldapAACertificateAttributeName);
			hash = addHashCode(hash, ldapAttributeDescriptorCertificateAttributeName);
			hash = addHashCode(hash, ldapAttributeCertificateRevocationListAttributeName);
			hash = addHashCode(hash, ldapAttributeAuthorityRevocationListAttributeName);
			hash = addHashCode(hash, userCertificateSubjectAttributeName);
			hash = addHashCode(hash, cACertificateSubjectAttributeName);
			hash = addHashCode(hash, crossCertificateSubjectAttributeName);
			hash = addHashCode(hash, certificateRevocationListIssuerAttributeName);
			hash = addHashCode(hash, deltaRevocationListIssuerAttributeName);
			hash = addHashCode(hash, authorityRevocationListIssuerAttributeName);
			hash = addHashCode(hash, attributeCertificateAttributeSubjectAttributeName);
			hash = addHashCode(hash, aACertificateSubjectAttributeName);
			hash = addHashCode(hash, attributeDescriptorCertificateSubjectAttributeName);
			hash = addHashCode(hash, attributeCertificateRevocationListIssuerAttributeName);
			hash = addHashCode(hash, attributeAuthorityRevocationListIssuerAttributeName);
			hash = addHashCode(hash, searchForSerialNumberIn);

			return hash;
		}

		private int addHashCode(int hashCode, object o)
		{
			return (hashCode * 29) + (o == null ? 0 : o.GetHashCode());
		}

		/// <returns> Returns the aACertificateAttribute. </returns>
		public virtual string getAACertificateAttribute()
		{
			return aACertificateAttribute;
		}

		/// <returns> Returns the aACertificateSubjectAttributeName. </returns>
		public virtual string getAACertificateSubjectAttributeName()
		{
			return aACertificateSubjectAttributeName;
		}

		/// <returns> Returns the attributeAuthorityRevocationListAttribute. </returns>
		public virtual string getAttributeAuthorityRevocationListAttribute()
		{
			return attributeAuthorityRevocationListAttribute;
		}

		/// <returns> Returns the attributeAuthorityRevocationListIssuerAttributeName. </returns>
		public virtual string getAttributeAuthorityRevocationListIssuerAttributeName()
		{
			return attributeAuthorityRevocationListIssuerAttributeName;
		}

		/// <returns> Returns the attributeCertificateAttributeAttribute. </returns>
		public virtual string getAttributeCertificateAttributeAttribute()
		{
			return attributeCertificateAttributeAttribute;
		}

		/// <returns> Returns the attributeCertificateAttributeSubjectAttributeName. </returns>
		public virtual string getAttributeCertificateAttributeSubjectAttributeName()
		{
			return attributeCertificateAttributeSubjectAttributeName;
		}

		/// <returns> Returns the attributeCertificateRevocationListAttribute. </returns>
		public virtual string getAttributeCertificateRevocationListAttribute()
		{
			return attributeCertificateRevocationListAttribute;
		}

		/// <returns> Returns the
		///         attributeCertificateRevocationListIssuerAttributeName. </returns>
		public virtual string getAttributeCertificateRevocationListIssuerAttributeName()
		{
			return attributeCertificateRevocationListIssuerAttributeName;
		}

		/// <returns> Returns the attributeDescriptorCertificateAttribute. </returns>
		public virtual string getAttributeDescriptorCertificateAttribute()
		{
			return attributeDescriptorCertificateAttribute;
		}

		/// <returns> Returns the attributeDescriptorCertificateSubjectAttributeName. </returns>
		public virtual string getAttributeDescriptorCertificateSubjectAttributeName()
		{
			return attributeDescriptorCertificateSubjectAttributeName;
		}

		/// <returns> Returns the authorityRevocationListAttribute. </returns>
		public virtual string getAuthorityRevocationListAttribute()
		{
			return authorityRevocationListAttribute;
		}

		/// <returns> Returns the authorityRevocationListIssuerAttributeName. </returns>
		public virtual string getAuthorityRevocationListIssuerAttributeName()
		{
			return authorityRevocationListIssuerAttributeName;
		}

		/// <returns> Returns the baseDN. </returns>
		public virtual string getBaseDN()
		{
			return baseDN;
		}

		/// <returns> Returns the cACertificateAttribute. </returns>
		public virtual string getCACertificateAttribute()
		{
			return cACertificateAttribute;
		}

		/// <returns> Returns the cACertificateSubjectAttributeName. </returns>
		public virtual string getCACertificateSubjectAttributeName()
		{
			return cACertificateSubjectAttributeName;
		}

		/// <returns> Returns the certificateRevocationListAttribute. </returns>
		public virtual string getCertificateRevocationListAttribute()
		{
			return certificateRevocationListAttribute;
		}

		/// <returns> Returns the certificateRevocationListIssuerAttributeName. </returns>
		public virtual string getCertificateRevocationListIssuerAttributeName()
		{
			return certificateRevocationListIssuerAttributeName;
		}

		/// <returns> Returns the crossCertificateAttribute. </returns>
		public virtual string getCrossCertificateAttribute()
		{
			return crossCertificateAttribute;
		}

		/// <returns> Returns the crossCertificateSubjectAttributeName. </returns>
		public virtual string getCrossCertificateSubjectAttributeName()
		{
			return crossCertificateSubjectAttributeName;
		}

		/// <returns> Returns the deltaRevocationListAttribute. </returns>
		public virtual string getDeltaRevocationListAttribute()
		{
			return deltaRevocationListAttribute;
		}

		/// <returns> Returns the deltaRevocationListIssuerAttributeName. </returns>
		public virtual string getDeltaRevocationListIssuerAttributeName()
		{
			return deltaRevocationListIssuerAttributeName;
		}

		/// <returns> Returns the ldapAACertificateAttributeName. </returns>
		public virtual string getLdapAACertificateAttributeName()
		{
			return ldapAACertificateAttributeName;
		}

		/// <returns> Returns the ldapAttributeAuthorityRevocationListAttributeName. </returns>
		public virtual string getLdapAttributeAuthorityRevocationListAttributeName()
		{
			return ldapAttributeAuthorityRevocationListAttributeName;
		}

		/// <returns> Returns the ldapAttributeCertificateAttributeAttributeName. </returns>
		public virtual string getLdapAttributeCertificateAttributeAttributeName()
		{
			return ldapAttributeCertificateAttributeAttributeName;
		}

		/// <returns> Returns the ldapAttributeCertificateRevocationListAttributeName. </returns>
		public virtual string getLdapAttributeCertificateRevocationListAttributeName()
		{
			return ldapAttributeCertificateRevocationListAttributeName;
		}

		/// <returns> Returns the ldapAttributeDescriptorCertificateAttributeName. </returns>
		public virtual string getLdapAttributeDescriptorCertificateAttributeName()
		{
			return ldapAttributeDescriptorCertificateAttributeName;
		}

		/// <returns> Returns the ldapAuthorityRevocationListAttributeName. </returns>
		public virtual string getLdapAuthorityRevocationListAttributeName()
		{
			return ldapAuthorityRevocationListAttributeName;
		}

		/// <returns> Returns the ldapCACertificateAttributeName. </returns>
		public virtual string getLdapCACertificateAttributeName()
		{
			return ldapCACertificateAttributeName;
		}

		/// <returns> Returns the ldapCertificateRevocationListAttributeName. </returns>
		public virtual string getLdapCertificateRevocationListAttributeName()
		{
			return ldapCertificateRevocationListAttributeName;
		}

		/// <returns> Returns the ldapCrossCertificateAttributeName. </returns>
		public virtual string getLdapCrossCertificateAttributeName()
		{
			return ldapCrossCertificateAttributeName;
		}

		/// <returns> Returns the ldapDeltaRevocationListAttributeName. </returns>
		public virtual string getLdapDeltaRevocationListAttributeName()
		{
			return ldapDeltaRevocationListAttributeName;
		}

		/// <returns> Returns the ldapURL. </returns>
		public virtual string getLdapURL()
		{
			return ldapURL;
		}

		/// <returns> Returns the ldapUserCertificateAttributeName. </returns>
		public virtual string getLdapUserCertificateAttributeName()
		{
			return ldapUserCertificateAttributeName;
		}

		/// <returns> Returns the searchForSerialNumberIn. </returns>
		public virtual string getSearchForSerialNumberIn()
		{
			return searchForSerialNumberIn;
		}

		/// <returns> Returns the userCertificateAttribute. </returns>
		public virtual string getUserCertificateAttribute()
		{
			return userCertificateAttribute;
		}

		/// <returns> Returns the userCertificateSubjectAttributeName. </returns>
		public virtual string getUserCertificateSubjectAttributeName()
		{
			return userCertificateSubjectAttributeName;
		}

		public static X509LDAPCertStoreParameters getInstance(LDAPCertStoreParameters @params)
		{
			string server = "ldap://" + @params.getServerName() + ":" + @params.getPort();
			X509LDAPCertStoreParameters _params = (new Builder(server, "")).build();
			return _params;
		}
	}

}