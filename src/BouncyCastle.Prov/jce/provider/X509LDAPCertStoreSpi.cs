using System;

namespace org.bouncycastle.jce.provider
{


	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using CertificatePair = org.bouncycastle.asn1.x509.CertificatePair;

	/// 
	/// <summary>
	/// This is a general purpose implementation to get X.509 certificates and CRLs
	/// from a LDAP location.
	/// <para>
	/// At first a search is performed in the ldap*AttributeNames of the
	/// <seealso cref="org.bouncycastle.jce.X509LDAPCertStoreParameters"/> with the given
	/// information of the subject (for all kind of certificates) or issuer (for
	/// CRLs), respectively, if a X509CertSelector is given with that details. For
	/// CRLs, CA certificates and cross certificates a coarse search is made only for
	/// entries with that content to get more possibly matching results.
	/// </para>
	/// </summary>
	public class X509LDAPCertStoreSpi : CertStoreSpi
	{
		private X509LDAPCertStoreParameters @params;

		public X509LDAPCertStoreSpi(CertStoreParameters @params) : base(@params)
		{

			if (!(@params is X509LDAPCertStoreParameters))
			{
				throw new InvalidAlgorithmParameterException(typeof(X509LDAPCertStoreSpi).getName() + ": parameter must be a " + typeof(X509LDAPCertStoreParameters).getName() + " object\n" + @params.ToString());
			}

			this.@params = (X509LDAPCertStoreParameters)@params;
		}

		/// <summary>
		/// Initial Context Factory.
		/// </summary>
		private static string LDAP_PROVIDER = "com.sun.jndi.ldap.LdapCtxFactory";

		/// <summary>
		/// Processing referrals..
		/// </summary>
		private static string REFERRALS_IGNORE = "ignore";

		/// <summary>
		/// Security level to be used for LDAP connections.
		/// </summary>
		private const string SEARCH_SECURITY_LEVEL = "none";

		/// <summary>
		/// Package Prefix for loading URL context factories.
		/// </summary>
		private const string URL_CONTEXT_PREFIX = "com.sun.jndi.url";

		private DirContext connectLDAP()
		{
			Properties props = new Properties();
			props.setProperty(Context.INITIAL_CONTEXT_FACTORY, LDAP_PROVIDER);
			props.setProperty(Context.BATCHSIZE, "0");

			props.setProperty(Context.PROVIDER_URL, @params.getLdapURL());
			props.setProperty(Context.URL_PKG_PREFIXES, URL_CONTEXT_PREFIX);
			props.setProperty(Context.REFERRAL, REFERRALS_IGNORE);
			props.setProperty(Context.SECURITY_AUTHENTICATION, SEARCH_SECURITY_LEVEL);

			DirContext ctx = new InitialDirContext(props);
			return ctx;
		}

		private string parseDN(string subject, string subjectAttributeName)
		{
			string temp = subject;
			int begin = temp.ToLower().IndexOf(subjectAttributeName.ToLower(), StringComparison.Ordinal);
			temp = temp.Substring(begin + subjectAttributeName.Length);
			int end = temp.IndexOf(',');
			if (end == -1)
			{
				end = temp.Length;
			}
			while (temp[end - 1] == '\\')
			{
				end = temp.IndexOf(',', end + 1);
				if (end == -1)
				{
					end = temp.Length;
				}
			}
			temp = temp.Substring(0, end);
			begin = temp.IndexOf('=');
			temp = temp.Substring(begin + 1);
			if (temp[0] == ' ')
			{
				temp = temp.Substring(1);
			}
			if (temp.StartsWith(@"""", StringComparison.Ordinal))
			{
				temp = temp.Substring(1);
			}
			if (temp.EndsWith(@"""", StringComparison.Ordinal))
			{
				temp = temp.Substring(0, temp.Length - 1);
			}
			return temp;
		}

		public virtual Collection engineGetCertificates(CertSelector selector)
		{
			if (!(selector is X509CertSelector))
			{
				throw new CertStoreException("selector is not a X509CertSelector");
			}
			X509CertSelector xselector = (X509CertSelector)selector;

			Set certSet = new HashSet();

			Set set = getEndCertificates(xselector);
			set.addAll(getCACertificates(xselector));
			set.addAll(getCrossCertificates(xselector));

			Iterator it = set.iterator();

			try
			{
				CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
				while (it.hasNext())
				{
					byte[] bytes = (byte[])it.next();
					if (bytes == null || bytes.Length == 0)
					{
						continue;
					}

					List bytesList = new ArrayList();
					bytesList.add(bytes);

					try
					{
						CertificatePair pair = CertificatePair.getInstance(new ASN1InputStream(bytes)
								.readObject());
						bytesList.clear();
						if (pair.getForward() != null)
						{
							bytesList.add(pair.getForward().getEncoded());
						}
						if (pair.getReverse() != null)
						{
							bytesList.add(pair.getReverse().getEncoded());
						}
					}
					catch (IOException)
					{

					}
					catch (IllegalArgumentException)
					{

					}
					for (Iterator it2 = bytesList.iterator(); it2.hasNext();)
					{
						ByteArrayInputStream bIn = new ByteArrayInputStream((byte[])it2.next());
						try
						{
							Certificate cert = cf.generateCertificate(bIn);
							// JavaSystem.@out.println(((X509Certificate)
							// cert).getSubjectX500Principal());
							if (xselector.match(cert))
							{
								certSet.add(cert);
							}
						}
						catch (Exception)
						{

						}
					}
				}
			}
			catch (Exception e)
			{
				throw new CertStoreException("certificate cannot be constructed from LDAP result: " + e);
			}

			return certSet;
		}

		private Set certSubjectSerialSearch(X509CertSelector xselector, string[] attrs, string attrName, string subjectAttributeName)
		{
			Set set = new HashSet();
			try
			{
				if (xselector.getSubjectAsBytes() != null || xselector.getSubjectAsString() != null || xselector.getCertificate() != null)
				{
					string subject = null;
					string serial = null;
					if (xselector.getCertificate() != null)
					{
						subject = xselector.getCertificate().getSubjectX500Principal().getName("RFC1779");
						serial = xselector.getCertificate().getSerialNumber().ToString();
					}
					else
					{
						if (xselector.getSubjectAsBytes() != null)
						{
							subject = (new X500Principal(xselector.getSubjectAsBytes())).getName("RFC1779");
						}
						else
						{
							subject = xselector.getSubjectAsString();
						}
					}
					string attrValue = parseDN(subject, subjectAttributeName);
					set.addAll(search(attrName, "*" + attrValue + "*", attrs));
					if (!string.ReferenceEquals(serial, null) && !string.ReferenceEquals(@params.getSearchForSerialNumberIn(), null))
					{
						attrValue = serial;
						attrName = @params.getSearchForSerialNumberIn();
						set.addAll(search(attrName, "*" + attrValue + "*", attrs));
					}
				}
				else
				{
					set.addAll(search(attrName, "*", attrs));
				}
			}
			catch (IOException e)
			{
				throw new CertStoreException("exception processing selector: " + e);
			}

			return set;
		}

		private Set getEndCertificates(X509CertSelector xselector)
		{
			string[] attrs = new string[] {@params.getUserCertificateAttribute()};
			string attrName = @params.getLdapUserCertificateAttributeName();
			string subjectAttributeName = @params.getUserCertificateSubjectAttributeName();

			Set set = certSubjectSerialSearch(xselector, attrs, attrName, subjectAttributeName);
			return set;
		}

		private Set getCACertificates(X509CertSelector xselector)
		{
			string[] attrs = new string[] {@params.getCACertificateAttribute()};
			string attrName = @params.getLdapCACertificateAttributeName();
			string subjectAttributeName = @params.getCACertificateSubjectAttributeName();
			Set set = certSubjectSerialSearch(xselector, attrs, attrName, subjectAttributeName);

			if (set.isEmpty())
			{
				set.addAll(search(null, "*", attrs));
			}

			return set;
		}

		private Set getCrossCertificates(X509CertSelector xselector)
		{
			string[] attrs = new string[] {@params.getCrossCertificateAttribute()};
			string attrName = @params.getLdapCrossCertificateAttributeName();
			string subjectAttributeName = @params.getCrossCertificateSubjectAttributeName();
			Set set = certSubjectSerialSearch(xselector, attrs, attrName, subjectAttributeName);

			if (set.isEmpty())
			{
				set.addAll(search(null, "*", attrs));
			}

			return set;
		}

		public virtual Collection engineGetCRLs(CRLSelector selector)
		{
			string[] attrs = new string[] {@params.getCertificateRevocationListAttribute()};
			if (!(selector is X509CRLSelector))
			{
				throw new CertStoreException("selector is not a X509CRLSelector");
			}
			X509CRLSelector xselector = (X509CRLSelector)selector;

			Set crlSet = new HashSet();

			string attrName = @params.getLdapCertificateRevocationListAttributeName();
			Set set = new HashSet();

			if (xselector.getIssuerNames() != null)
			{
				for (Iterator it = xselector.getIssuerNames().iterator(); it.hasNext();)
				{
					object o = it.next();
					string attrValue = null;
					if (o is string)
					{
						string issuerAttributeName = @params.getCertificateRevocationListIssuerAttributeName();
						attrValue = parseDN((string)o, issuerAttributeName);
					}
					else
					{
						string issuerAttributeName = @params.getCertificateRevocationListIssuerAttributeName();
						attrValue = parseDN(new X500Principal((byte[])o)
							.getName("RFC1779"), issuerAttributeName);
					}
					set.addAll(search(attrName, "*" + attrValue + "*", attrs));
				}
			}
			else
			{
				set.addAll(search(attrName, "*", attrs));
			}
			set.addAll(search(null, "*", attrs));
			Iterator it = set.iterator();

			try
			{
				CertificateFactory cf = CertificateFactory.getInstance("X.509", BouncyCastleProvider.PROVIDER_NAME);
				while (it.hasNext())
				{
					CRL crl = cf.generateCRL(new ByteArrayInputStream((byte[])it.next()));
					if (xselector.match(crl))
					{
						crlSet.add(crl);
					}
				}
			}
			catch (Exception e)
			{
				throw new CertStoreException("CRL cannot be constructed from LDAP result " + e);
			}

			return crlSet;
		}

		/// <summary>
		/// Returns a Set of byte arrays with the certificate or CRL encodings.
		/// </summary>
		/// <param name="attributeName">  The attribute name to look for in the LDAP. </param>
		/// <param name="attributeValue"> The value the attribute name must have. </param>
		/// <param name="attrs">          The attributes in the LDAP which hold the certificate,
		///                       certificate pair or CRL in a found entry. </param>
		/// <returns> Set of byte arrays with the certificate encodings. </returns>
		private Set search(string attributeName, string attributeValue, string[] attrs)
		{
			string filter = attributeName + "=" + attributeValue;
			if (string.ReferenceEquals(attributeName, null))
			{
				filter = null;
			}
			DirContext ctx = null;
			Set set = new HashSet();
			try
			{

				ctx = connectLDAP();

				SearchControls constraints = new SearchControls();
				constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
				constraints.setCountLimit(0);
				for (int i = 0; i < attrs.Length; i++)
				{
					string[] temp = new string[1];
					temp[0] = attrs[i];
					constraints.setReturningAttributes(temp);

					string filter2 = "(&(" + filter + ")(" + temp[0] + "=*))";
					if (string.ReferenceEquals(filter, null))
					{
						filter2 = "(" + temp[0] + "=*)";
					}
					NamingEnumeration results = ctx.search(@params.getBaseDN(), filter2, constraints);
					while (results.hasMoreElements())
					{
						SearchResult sr = (SearchResult)results.next();
						// should only be one attribute in the attribute set with
						// one
						// attribute value as byte array
						NamingEnumeration enumeration = ((Attribute)(sr.getAttributes().getAll().next())).getAll();
						while (enumeration.hasMore())
						{
							object o = enumeration.next();
							set.add(o);
						}
					}
				}
			}
			catch (Exception e)
			{
				throw new CertStoreException("Error getting results from LDAP directory " + e);

			}
			finally
			{
				try
				{
					if (null != ctx)
					{
						ctx.close();
					}
				}
				catch (Exception)
				{
				}
			}
			return set;
		}

	}

}