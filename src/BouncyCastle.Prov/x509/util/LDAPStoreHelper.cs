using System;

namespace org.bouncycastle.x509.util
{


	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificatePair = org.bouncycastle.asn1.x509.CertificatePair;
	using X509LDAPCertStoreParameters = org.bouncycastle.jce.X509LDAPCertStoreParameters;
	using X509AttrCertParser = org.bouncycastle.jce.provider.X509AttrCertParser;
	using X509CRLParser = org.bouncycastle.jce.provider.X509CRLParser;
	using X509CertPairParser = org.bouncycastle.jce.provider.X509CertPairParser;
	using X509CertParser = org.bouncycastle.jce.provider.X509CertParser;
	using StoreException = org.bouncycastle.util.StoreException;

	/// <summary>
	/// This is a general purpose implementation to get X.509 certificates, CRLs,
	/// attribute certificates and cross certificates from a LDAP location.
	/// <para>
	/// At first a search is performed in the ldap*AttributeNames of the
	/// <seealso cref="org.bouncycastle.jce.X509LDAPCertStoreParameters"/> with the given
	/// information of the subject (for all kind of certificates) or issuer (for
	/// CRLs), respectively, if a <seealso cref="org.bouncycastle.x509.X509CertStoreSelector"/> or
	/// <seealso cref="org.bouncycastle.x509.X509AttributeCertificate"/> is given with that
	/// details.
	/// </para>
	/// </para><para>
	/// For the used schemes see:
	/// <ul>
	/// <li><a href="http://www.ietf.org/rfc/rfc2587.txt">RFC 2587</a>
	/// <li><a
	/// href="http://www3.ietf.org/proceedings/01mar/I-D/pkix-ldap-schema-01.txt">Internet
	/// X.509 Public Key Infrastructure Additional LDAP Schema for PKIs and PMIs</a>
	/// </ul>
	/// </summary>
	public class LDAPStoreHelper
	{

		// TODO: cache results

		private X509LDAPCertStoreParameters @params;

		public LDAPStoreHelper(X509LDAPCertStoreParameters @params)
		{
			this.@params = @params;
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

		private string parseDN(string subject, string dNAttributeName)
		{
			string temp = subject;
			int begin = temp.ToLower().IndexOf(dNAttributeName.ToLower() + "=", StringComparison.Ordinal);
			if (begin == -1)
			{
				return "";
			}
			temp = temp.Substring(begin + dNAttributeName.Length);
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

		private Set createCerts(List list, X509CertStoreSelector xselector)
		{
			Set certSet = new HashSet();

			Iterator it = list.iterator();
			X509CertParser parser = new X509CertParser();
			while (it.hasNext())
			{
				try
				{
					parser.engineInit(new ByteArrayInputStream((byte[])it.next()));
					X509Certificate cert = (X509Certificate)parser.engineRead();
					if (xselector.match((object)cert))
					{
						certSet.add(cert);
					}

				}
				catch (Exception)
				{

				}
			}

			return certSet;
		}

		/// <summary>
		/// Can use the subject and serial and the subject and serialNumber of the
		/// certificate of the given of the X509CertStoreSelector. If a certificate
		/// for checking is given this has higher precedence.
		/// </summary>
		/// <param name="xselector">             The selector with the search criteria. </param>
		/// <param name="attrs">                 Attributes which contain the certificates in the LDAP
		///                              directory. </param>
		/// <param name="attrNames">             Attribute names in teh LDAP directory which correspond to the
		///                              subjectAttributeNames. </param>
		/// <param name="subjectAttributeNames"> Subject attribute names (like "CN", "O", "OU") to use to
		///                              search in the LDAP directory </param>
		/// <returns> A list of found DER encoded certificates. </returns>
		/// <exception cref="StoreException"> if an error occurs while searching. </exception>
		private List certSubjectSerialSearch(X509CertStoreSelector xselector, string[] attrs, string[] attrNames, string[] subjectAttributeNames)
		{
			// TODO: support also subjectAltNames?
			List list = new ArrayList();

			string subject = null;
			string serial = null;

			subject = getSubjectAsString(xselector);

			if (xselector.getSerialNumber() != null)
			{
				serial = xselector.getSerialNumber().ToString();
			}
			if (xselector.getCertificate() != null)
			{
				subject = xselector.getCertificate().getSubjectX500Principal().getName("RFC1779");
				serial = xselector.getCertificate().getSerialNumber().ToString();
			}

			string attrValue = null;
			if (!string.ReferenceEquals(subject, null))
			{
				for (int i = 0; i < subjectAttributeNames.Length; i++)
				{
					attrValue = parseDN(subject, subjectAttributeNames[i]);
					list.addAll(search(attrNames, "*" + attrValue + "*", attrs));
				}
			}
			if (!string.ReferenceEquals(serial, null) && !string.ReferenceEquals(@params.getSearchForSerialNumberIn(), null))
			{
				attrValue = serial;
				list.addAll(search(splitString(@params.getSearchForSerialNumberIn()), attrValue, attrs));
			}
			if (string.ReferenceEquals(serial, null) && string.ReferenceEquals(subject, null))
			{
				list.addAll(search(attrNames, "*", attrs));
			}

			return list;
		}



		/// <summary>
		/// Can use the subject of the forward certificate of the set certificate
		/// pair or the subject of the forward
		/// <seealso cref="org.bouncycastle.x509.X509CertStoreSelector"/> of the given
		/// selector.
		/// </summary>
		/// <param name="xselector">             The selector with the search criteria. </param>
		/// <param name="attrs">                 Attributes which contain the attribute certificates in the
		///                              LDAP directory. </param>
		/// <param name="attrNames">             Attribute names in the LDAP directory which correspond to the
		///                              subjectAttributeNames. </param>
		/// <param name="subjectAttributeNames"> Subject attribute names (like "CN", "O", "OU") to use to
		///                              search in the LDAP directory </param>
		/// <returns> A list of found DER encoded certificate pairs. </returns>
		/// <exception cref="StoreException"> if an error occurs while searching. </exception>
		private List crossCertificatePairSubjectSearch(X509CertPairStoreSelector xselector, string[] attrs, string[] attrNames, string[] subjectAttributeNames)
		{
			List list = new ArrayList();

			// search for subject
			string subject = null;

			if (xselector.getForwardSelector() != null)
			{
				subject = getSubjectAsString(xselector.getForwardSelector());
			}
			if (xselector.getCertPair() != null)
			{
				if (xselector.getCertPair().getForward() != null)
				{
					subject = xselector.getCertPair().getForward().getSubjectX500Principal().getName("RFC1779");
				}
			}
			string attrValue = null;
			if (!string.ReferenceEquals(subject, null))
			{
				for (int i = 0; i < subjectAttributeNames.Length; i++)
				{
					attrValue = parseDN(subject, subjectAttributeNames[i]);
					list.addAll(search(attrNames, "*" + attrValue + "*", attrs));
				}
			}
			if (string.ReferenceEquals(subject, null))
			{
				list.addAll(search(attrNames, "*", attrs));
			}

			return list;
		}

		/// <summary>
		/// Can use the entityName of the holder of the attribute certificate, the
		/// serialNumber of attribute certificate and the serialNumber of the
		/// associated certificate of the given of the X509AttributeCertSelector.
		/// </summary>
		/// <param name="xselector">             The selector with the search criteria. </param>
		/// <param name="attrs">                 Attributes which contain the attribute certificates in the
		///                              LDAP directory. </param>
		/// <param name="attrNames">             Attribute names in the LDAP directory which correspond to the
		///                              subjectAttributeNames. </param>
		/// <param name="subjectAttributeNames"> Subject attribute names (like "CN", "O", "OU") to use to
		///                              search in the LDAP directory </param>
		/// <returns> A list of found DER encoded attribute certificates. </returns>
		/// <exception cref="StoreException"> if an error occurs while searching. </exception>
		private List attrCertSubjectSerialSearch(X509AttributeCertStoreSelector xselector, string[] attrs, string[] attrNames, string[] subjectAttributeNames)
		{
			List list = new ArrayList();

			// search for serialNumber of associated cert,
			// serialNumber of the attribute certificate or DN in the entityName
			// of the holder

			string subject = null;
			string serial = null;

			Collection serials = new HashSet();
			Principal[] principals = null;
			if (xselector.getHolder() != null)
			{
				// serialNumber of associated cert
				if (xselector.getHolder().getSerialNumber() != null)
				{
					serials.add(xselector.getHolder().getSerialNumber().ToString());
				}
				// DN in the entityName of the holder
				if (xselector.getHolder().getEntityNames() != null)
				{
					principals = xselector.getHolder().getEntityNames();
				}
			}

			if (xselector.getAttributeCert() != null)
			{
				if (xselector.getAttributeCert().getHolder().getEntityNames() != null)
				{
					principals = xselector.getAttributeCert().getHolder().getEntityNames();
				}
				// serialNumber of the attribute certificate
				serials.add(xselector.getAttributeCert().getSerialNumber().ToString());
			}
			if (principals != null)
			{
				// only first should be relevant
				if (principals[0] is X500Principal)
				{
					subject = ((X500Principal)principals[0]).getName("RFC1779");
				}
				else
				{
					// strange ...
					subject = principals[0].getName();
				}
			}
			if (xselector.getSerialNumber() != null)
			{
				serials.add(xselector.getSerialNumber().ToString());
			}

			string attrValue = null;
			if (!string.ReferenceEquals(subject, null))
			{
				for (int i = 0; i < subjectAttributeNames.Length; i++)
				{
					attrValue = parseDN(subject, subjectAttributeNames[i]);
					list.addAll(search(attrNames, "*" + attrValue + "*", attrs));
				}
			}
			if (serials.size() > 0 && !string.ReferenceEquals(@params.getSearchForSerialNumberIn(), null))
			{
				Iterator it = serials.iterator();
				while (it.hasNext())
				{
					serial = (string)it.next();
					list.addAll(search(splitString(@params.getSearchForSerialNumberIn()), serial, attrs));
				}
			}
			if (serials.size() == 0 && string.ReferenceEquals(subject, null))
			{
				list.addAll(search(attrNames, "*", attrs));
			}

			return list;
		}

		/// <summary>
		/// Can use the issuer of the given of the X509CRLStoreSelector.
		/// </summary>
		/// <param name="xselector">            The selector with the search criteria. </param>
		/// <param name="attrs">                Attributes which contain the attribute certificates in the
		///                             LDAP directory. </param>
		/// <param name="attrNames">            Attribute names in the LDAP directory which correspond to the
		///                             subjectAttributeNames. </param>
		/// <param name="issuerAttributeNames"> Issuer attribute names (like "CN", "O", "OU") to use to search
		///                             in the LDAP directory </param>
		/// <returns> A list of found DER encoded CRLs. </returns>
		/// <exception cref="StoreException"> if an error occurs while searching. </exception>
		private List cRLIssuerSearch(X509CRLStoreSelector xselector, string[] attrs, string[] attrNames, string[] issuerAttributeNames)
		{
			List list = new ArrayList();

			string issuer = null;
			Collection issuers = new HashSet();
			if (xselector.getIssuers() != null)
			{
				issuers.addAll(xselector.getIssuers());
			}
			if (xselector.getCertificateChecking() != null)
			{
				issuers.add(getCertificateIssuer(xselector.getCertificateChecking()));
			}
			if (xselector.getAttrCertificateChecking() != null)
			{
				Principal[] principals = xselector.getAttrCertificateChecking().getIssuer().getPrincipals();
				for (int i = 0; i < principals.Length; i++)
				{
					if (principals[i] is X500Principal)
					{
						issuers.add(principals[i]);
					}
				}
			}
			Iterator it = issuers.iterator();
			while (it.hasNext())
			{
				issuer = ((X500Principal)it.next()).getName("RFC1779");
				string attrValue = null;

				for (int i = 0; i < issuerAttributeNames.Length; i++)
				{
					attrValue = parseDN(issuer, issuerAttributeNames[i]);
					list.addAll(search(attrNames, "*" + attrValue + "*", attrs));
				}
			}
			if (string.ReferenceEquals(issuer, null))
			{
				list.addAll(search(attrNames, "*", attrs));
			}

			return list;
		}

		/// <summary>
		/// Returns a <code>List</code> of encodings of the certificates, attribute
		/// certificates, CRL or certificate pairs.
		/// </summary>
		/// <param name="attributeNames"> The attribute names to look for in the LDAP. </param>
		/// <param name="attributeValue"> The value the attribute name must have. </param>
		/// <param name="attrs">          The attributes in the LDAP which hold the certificate,
		///                       attribute certificate, certificate pair or CRL in a found
		///                       entry. </param>
		/// <returns> A <code>List</code> of byte arrays with the encodings. </returns>
		/// <exception cref="StoreException"> if an error occurs getting the results from the LDAP
		///                        directory. </exception>
		private List search(string[] attributeNames, string attributeValue, string[] attrs)
		{
			string filter = null;
			if (attributeNames == null)
			{
				filter = null;
			}
			else
			{
				filter = "";
				if (attributeValue.Equals("**"))
				{
					attributeValue = "*";
				}
				for (int i = 0; i < attributeNames.Length; i++)
				{
					filter += "(" + attributeNames[i] + "=" + attributeValue + ")";
				}
				filter = "(|" + filter + ")";
			}
			string filter2 = "";
			for (int i = 0; i < attrs.Length; i++)
			{
				filter2 += "(" + attrs[i] + "=*)";
			}
			filter2 = "(|" + filter2 + ")";

			string filter3 = "(&" + filter + "" + filter2 + ")";
			if (string.ReferenceEquals(filter, null))
			{
				filter3 = filter2;
			}
			List list;
			list = getFromCache(filter3);
			if (list != null)
			{
				return list;
			}
			DirContext ctx = null;
			list = new ArrayList();
			try
			{

				ctx = connectLDAP();

				SearchControls constraints = new SearchControls();
				constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
				constraints.setCountLimit(0);
				constraints.setReturningAttributes(attrs);
				NamingEnumeration results = ctx.search(@params.getBaseDN(), filter3, constraints);
				while (results.hasMoreElements())
				{
					SearchResult sr = (SearchResult)results.next();
					NamingEnumeration enumeration = ((Attribute)(sr.getAttributes().getAll().next())).getAll();
					while (enumeration.hasMore())
					{
						list.add(enumeration.next());
					}
				}
				addToCache(filter3, list);
			}
			catch (NamingException)
			{
				// skip exception, unfortunately if an attribute type is not
				// supported an exception is thrown

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
			return list;
		}

		private Set createCRLs(List list, X509CRLStoreSelector xselector)
		{
			Set crlSet = new HashSet();

			X509CRLParser parser = new X509CRLParser();
			Iterator it = list.iterator();
			while (it.hasNext())
			{
				try
				{
					parser.engineInit(new ByteArrayInputStream((byte[])it.next()));
					X509CRL crl = (X509CRL)parser.engineRead();
					if (xselector.match((object)crl))
					{
						crlSet.add(crl);
					}
				}
				catch (StreamParsingException)
				{

				}
			}

			return crlSet;
		}

		private Set createCrossCertificatePairs(List list, X509CertPairStoreSelector xselector)
		{
			Set certPairSet = new HashSet();

			int i = 0;
			while (i < list.size())
			{
				X509CertificatePair pair;
				try
				{
					// first try to decode it as certificate pair
					try
					{
						X509CertPairParser parser = new X509CertPairParser();
						parser.engineInit(new ByteArrayInputStream((byte[])list.get(i)));
						pair = (X509CertificatePair)parser.engineRead();
					}
					catch (StreamParsingException)
					{
						// now try it to construct it the forward and reverse
						// certificate
						byte[] forward = (byte[])list.get(i);
						byte[] reverse = (byte[])list.get(i + 1);
						pair = new X509CertificatePair(new CertificatePair(Certificate.getInstance((new ASN1InputStream(forward)).readObject()), Certificate.getInstance((new ASN1InputStream(reverse)).readObject())));
						i++;
					}
					if (xselector.match((object)pair))
					{
						certPairSet.add(pair);
					}
				}
				catch (CertificateParsingException)
				{
					// try next
				}
				catch (IOException)
				{
					// try next
				}
				i++;
			}

			return certPairSet;
		}

		private Set createAttributeCertificates(List list, X509AttributeCertStoreSelector xselector)
		{
			Set certSet = new HashSet();

			Iterator it = list.iterator();
			X509AttrCertParser parser = new X509AttrCertParser();
			while (it.hasNext())
			{
				try
				{
					parser.engineInit(new ByteArrayInputStream((byte[])it.next()));
					X509AttributeCertificate cert = (X509AttributeCertificate)parser.engineRead();
					if (xselector.match((object)cert))
					{
						certSet.add(cert);
					}
				}
				catch (StreamParsingException)
				{

				}
			}

			return certSet;
		}

		/// <summary>
		/// Returns the CRLs for issued certificates for other CAs matching the given
		/// selector. <br>
		/// The authorityRevocationList attribute includes revocation information
		/// regarding certificates issued to other CAs.
		/// </summary>
		/// <param name="selector"> The CRL selector to use to find the CRLs. </param>
		/// <returns> A possible empty collection with CRLs </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getAuthorityRevocationLists(X509CRLStoreSelector selector)
		{
			string[] attrs = splitString(@params.getAuthorityRevocationListAttribute());
			string[] attrNames = splitString(@params.getLdapAuthorityRevocationListAttributeName());
			string[] issuerAttributeNames = splitString(@params.getAuthorityRevocationListIssuerAttributeName());

			List list = cRLIssuerSearch(selector, attrs, attrNames, issuerAttributeNames);
			Set resultSet = createCRLs(list, selector);
			if (resultSet.size() == 0)
			{
				X509CRLStoreSelector emptySelector = new X509CRLStoreSelector();
				list = cRLIssuerSearch(emptySelector, attrs, attrNames, issuerAttributeNames);

				resultSet.addAll(createCRLs(list, selector));
			}
			return resultSet;
		}

		/// <summary>
		/// Returns the revocation list for revoked attribute certificates.
		/// <para>
		/// The attributeCertificateRevocationList holds a list of attribute
		/// certificates that have been revoked.
		/// </para> </summary>
		/// <param name="selector"> The CRL selector to use to find the CRLs. </param>
		/// <returns> A possible empty collection with CRLs. </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getAttributeCertificateRevocationLists(X509CRLStoreSelector selector)
		{
			string[] attrs = splitString(@params.getAttributeCertificateRevocationListAttribute());
			string[] attrNames = splitString(@params.getLdapAttributeCertificateRevocationListAttributeName());
			string[] issuerAttributeNames = splitString(@params.getAttributeCertificateRevocationListIssuerAttributeName());

			List list = cRLIssuerSearch(selector, attrs, attrNames, issuerAttributeNames);
			Set resultSet = createCRLs(list, selector);
			if (resultSet.size() == 0)
			{
				X509CRLStoreSelector emptySelector = new X509CRLStoreSelector();
				list = cRLIssuerSearch(emptySelector, attrs, attrNames, issuerAttributeNames);

				resultSet.addAll(createCRLs(list, selector));
			}
			return resultSet;
		}

		/// <summary>
		/// Returns the revocation list for revoked attribute certificates for an
		/// attribute authority
		/// <para>
		/// The attributeAuthorityList holds a list of AA certificates that have been
		/// revoked.
		/// </para> </summary>
		/// <param name="selector"> The CRL selector to use to find the CRLs. </param>
		/// <returns> A possible empty collection with CRLs </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getAttributeAuthorityRevocationLists(X509CRLStoreSelector selector)
		{
			string[] attrs = splitString(@params.getAttributeAuthorityRevocationListAttribute());
			string[] attrNames = splitString(@params.getLdapAttributeAuthorityRevocationListAttributeName());
			string[] issuerAttributeNames = splitString(@params.getAttributeAuthorityRevocationListIssuerAttributeName());

			List list = cRLIssuerSearch(selector, attrs, attrNames, issuerAttributeNames);
			Set resultSet = createCRLs(list, selector);
			if (resultSet.size() == 0)
			{
				X509CRLStoreSelector emptySelector = new X509CRLStoreSelector();
				list = cRLIssuerSearch(emptySelector, attrs, attrNames, issuerAttributeNames);

				resultSet.addAll(createCRLs(list, selector));
			}
			return resultSet;
		}

		/// <summary>
		/// Returns cross certificate pairs.
		/// </summary>
		/// <param name="selector"> The selector to use to find the cross certificates. </param>
		/// <returns> A possible empty collection with <seealso cref="X509CertificatePair"/>s </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getCrossCertificatePairs(X509CertPairStoreSelector selector)
		{
			string[] attrs = splitString(@params.getCrossCertificateAttribute());
			string[] attrNames = splitString(@params.getLdapCrossCertificateAttributeName());
			string[] subjectAttributeNames = splitString(@params.getCrossCertificateSubjectAttributeName());
			List list = crossCertificatePairSubjectSearch(selector, attrs, attrNames, subjectAttributeNames);
			Set resultSet = createCrossCertificatePairs(list, selector);
			if (resultSet.size() == 0)
			{
				X509CertStoreSelector emptyCertselector = new X509CertStoreSelector();
				X509CertPairStoreSelector emptySelector = new X509CertPairStoreSelector();

				emptySelector.setForwardSelector(emptyCertselector);
				emptySelector.setReverseSelector(emptyCertselector);
				list = crossCertificatePairSubjectSearch(emptySelector, attrs, attrNames, subjectAttributeNames);
				resultSet.addAll(createCrossCertificatePairs(list, selector));
			}
			return resultSet;
		}

		/// <summary>
		/// Returns end certificates.
		/// <para>
		/// The attributeDescriptorCertificate is self signed by a source of
		/// authority and holds a description of the privilege and its delegation
		/// rules.
		/// 
		/// </para>
		/// </summary>
		/// <param name="selector"> The selector to find the certificates. </param>
		/// <returns> A possible empty collection with certificates. </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getUserCertificates(X509CertStoreSelector selector)
		{
			string[] attrs = splitString(@params.getUserCertificateAttribute());
			string[] attrNames = splitString(@params.getLdapUserCertificateAttributeName());
			string[] subjectAttributeNames = splitString(@params.getUserCertificateSubjectAttributeName());

			List list = certSubjectSerialSearch(selector, attrs, attrNames, subjectAttributeNames);
			Set resultSet = createCerts(list, selector);
			if (resultSet.size() == 0)
			{
				X509CertStoreSelector emptySelector = new X509CertStoreSelector();
				list = certSubjectSerialSearch(emptySelector, attrs, attrNames, subjectAttributeNames);
				resultSet.addAll(createCerts(list, selector));
			}

			return resultSet;
		}

		/// <summary>
		/// Returns attribute certificates for an attribute authority
		/// <para>
		/// The aAcertificate holds the privileges of an attribute authority.
		/// </para> </summary>
		/// <param name="selector"> The selector to find the attribute certificates. </param>
		/// <returns> A possible empty collection with attribute certificates. </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getAACertificates(X509AttributeCertStoreSelector selector)
		{
			string[] attrs = splitString(@params.getAACertificateAttribute());
			string[] attrNames = splitString(@params.getLdapAACertificateAttributeName());
			string[] subjectAttributeNames = splitString(@params.getAACertificateSubjectAttributeName());

			List list = attrCertSubjectSerialSearch(selector, attrs, attrNames, subjectAttributeNames);
			Set resultSet = createAttributeCertificates(list, selector);
			if (resultSet.size() == 0)
			{
				X509AttributeCertStoreSelector emptySelector = new X509AttributeCertStoreSelector();
				list = attrCertSubjectSerialSearch(emptySelector, attrs, attrNames, subjectAttributeNames);
				resultSet.addAll(createAttributeCertificates(list, selector));
			}

			return resultSet;
		}

		/// <summary>
		/// Returns an attribute certificate for an authority
		/// <para>
		/// The attributeDescriptorCertificate is self signed by a source of
		/// authority and holds a description of the privilege and its delegation
		/// rules.
		/// </para> </summary>
		/// <param name="selector"> The selector to find the attribute certificates. </param>
		/// <returns> A possible empty collection with attribute certificates. </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getAttributeDescriptorCertificates(X509AttributeCertStoreSelector selector)
		{
			string[] attrs = splitString(@params.getAttributeDescriptorCertificateAttribute());
			string[] attrNames = splitString(@params.getLdapAttributeDescriptorCertificateAttributeName());
			string[] subjectAttributeNames = splitString(@params.getAttributeDescriptorCertificateSubjectAttributeName());

			List list = attrCertSubjectSerialSearch(selector, attrs, attrNames, subjectAttributeNames);
			Set resultSet = createAttributeCertificates(list, selector);
			if (resultSet.size() == 0)
			{
				X509AttributeCertStoreSelector emptySelector = new X509AttributeCertStoreSelector();
				list = attrCertSubjectSerialSearch(emptySelector, attrs, attrNames, subjectAttributeNames);
				resultSet.addAll(createAttributeCertificates(list, selector));
			}

			return resultSet;
		}

		/// <summary>
		/// Returns CA certificates.
		/// <para>
		/// The cACertificate attribute of a CA's directory entry shall be used to
		/// store self-issued certificates (if any) and certificates issued to this
		/// CA by CAs in the same realm as this CA.
		/// </para> </summary>
		/// <param name="selector"> The selector to find the certificates. </param>
		/// <returns> A possible empty collection with certificates. </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getCACertificates(X509CertStoreSelector selector)
		{
			string[] attrs = splitString(@params.getCACertificateAttribute());
			string[] attrNames = splitString(@params.getLdapCACertificateAttributeName());
			string[] subjectAttributeNames = splitString(@params.getCACertificateSubjectAttributeName());
			List list = certSubjectSerialSearch(selector, attrs, attrNames, subjectAttributeNames);
			Set resultSet = createCerts(list, selector);
			if (resultSet.size() == 0)
			{
				X509CertStoreSelector emptySelector = new X509CertStoreSelector();
				list = certSubjectSerialSearch(emptySelector, attrs, attrNames, subjectAttributeNames);
				resultSet.addAll(createCerts(list, selector));
			}
			return resultSet;
		}

		/// <summary>
		/// Returns the delta revocation list for revoked certificates.
		/// </summary>
		/// <param name="selector"> The CRL selector to use to find the CRLs. </param>
		/// <returns> A possible empty collection with CRLs. </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getDeltaCertificateRevocationLists(X509CRLStoreSelector selector)
		{
			string[] attrs = splitString(@params.getDeltaRevocationListAttribute());
			string[] attrNames = splitString(@params.getLdapDeltaRevocationListAttributeName());
			string[] issuerAttributeNames = splitString(@params.getDeltaRevocationListIssuerAttributeName());
			List list = cRLIssuerSearch(selector, attrs, attrNames, issuerAttributeNames);
			Set resultSet = createCRLs(list, selector);
			if (resultSet.size() == 0)
			{
				X509CRLStoreSelector emptySelector = new X509CRLStoreSelector();
				list = cRLIssuerSearch(emptySelector, attrs, attrNames, issuerAttributeNames);

				resultSet.addAll(createCRLs(list, selector));
			}
			return resultSet;
		}

		/// <summary>
		/// Returns an attribute certificate for an user.
		/// <para>
		/// The attributeCertificateAttribute holds the privileges of a user
		/// </para> </summary>
		/// <param name="selector"> The selector to find the attribute certificates. </param>
		/// <returns> A possible empty collection with attribute certificates. </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getAttributeCertificateAttributes(X509AttributeCertStoreSelector selector)
		{
			string[] attrs = splitString(@params.getAttributeCertificateAttributeAttribute());
			string[] attrNames = splitString(@params.getLdapAttributeCertificateAttributeAttributeName());
			string[] subjectAttributeNames = splitString(@params.getAttributeCertificateAttributeSubjectAttributeName());
			List list = attrCertSubjectSerialSearch(selector, attrs, attrNames, subjectAttributeNames);
			Set resultSet = createAttributeCertificates(list, selector);
			if (resultSet.size() == 0)
			{
				X509AttributeCertStoreSelector emptySelector = new X509AttributeCertStoreSelector();
				list = attrCertSubjectSerialSearch(emptySelector, attrs, attrNames, subjectAttributeNames);
				resultSet.addAll(createAttributeCertificates(list, selector));
			}

			return resultSet;
		}

		/// <summary>
		/// Returns the certificate revocation lists for revoked certificates.
		/// </summary>
		/// <param name="selector"> The CRL selector to use to find the CRLs. </param>
		/// <returns> A possible empty collection with CRLs. </returns>
		/// <exception cref="StoreException"> </exception>
		public virtual Collection getCertificateRevocationLists(X509CRLStoreSelector selector)
		{
			string[] attrs = splitString(@params.getCertificateRevocationListAttribute());
			string[] attrNames = splitString(@params.getLdapCertificateRevocationListAttributeName());
			string[] issuerAttributeNames = splitString(@params.getCertificateRevocationListIssuerAttributeName());
			List list = cRLIssuerSearch(selector, attrs, attrNames, issuerAttributeNames);
			Set resultSet = createCRLs(list, selector);
			if (resultSet.size() == 0)
			{
				X509CRLStoreSelector emptySelector = new X509CRLStoreSelector();
				list = cRLIssuerSearch(emptySelector, attrs, attrNames, issuerAttributeNames);

				resultSet.addAll(createCRLs(list, selector));
			}
			return resultSet;
		}

		private Map cacheMap = new HashMap(cacheSize);

		private static int cacheSize = 32;

		private static long lifeTime = 60 * 1000;

		private void addToCache(string searchCriteria, List list)
		{
			lock (this)
			{
				Date now = new Date(System.currentTimeMillis());
				List cacheEntry = new ArrayList();
				cacheEntry.add(now);
				cacheEntry.add(list);
				if (cacheMap.containsKey(searchCriteria))
				{
					cacheMap.put(searchCriteria, cacheEntry);
				}
				else
				{
					if (cacheMap.size() >= cacheSize)
					{
						// replace oldest
						Iterator it = cacheMap.entrySet().iterator();
						long oldest = now.getTime();
						object replace = null;
						while (it.hasNext())
						{
							Map.Entry entry = (Map.Entry)it.next();
							long current = ((Date)((List)entry.getValue()).get(0)).getTime();
							if (current < oldest)
							{
								oldest = current;
								replace = entry.getKey();
							}
						}
						cacheMap.remove(replace);
					}
					cacheMap.put(searchCriteria, cacheEntry);
				}
			}
		}

		private List getFromCache(string searchCriteria)
		{
			List entry = (List)cacheMap.get(searchCriteria);
			long now = System.currentTimeMillis();
			if (entry != null)
			{
				// too old
				if (((Date)entry.get(0)).getTime() < (now - lifeTime))
				{
					return null;
				}
				return (List)entry.get(1);
			}
			return null;
		}

		/*
		 * spilt string based on spaces
		 */
		private string[] splitString(string str)
		{
			return str.Split(@"\s+", true);
		}

		private string getSubjectAsString(X509CertStoreSelector xselector)
		{
			try
			{
				byte[] encSubject = xselector.getSubjectAsBytes();
				if (encSubject != null)
				{
					return (new X500Principal(encSubject)).getName("RFC1779");
				}
			}
			catch (IOException e)
			{
				throw new StoreException("exception processing name: " + e.Message, e);
			}
			return null;
		}

		private X500Principal getCertificateIssuer(X509Certificate cert)
		{
			return cert.getIssuerX500Principal();
		}
	}

}