using org.bouncycastle.asn1.isismtt;

using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Enumerated = org.bouncycastle.asn1.ASN1Enumerated;
	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1OutputStream = org.bouncycastle.asn1.ASN1OutputStream;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using ISISMTTObjectIdentifiers = org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using RFC4519Style = org.bouncycastle.asn1.x500.style.RFC4519Style;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using CRLDistPoint = org.bouncycastle.asn1.x509.CRLDistPoint;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using DistributionPoint = org.bouncycastle.asn1.x509.DistributionPoint;
	using DistributionPointName = org.bouncycastle.asn1.x509.DistributionPointName;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using PolicyInformation = org.bouncycastle.asn1.x509.PolicyInformation;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using PKIXCRLStore = org.bouncycastle.jcajce.PKIXCRLStore;
	using PKIXCRLStoreSelector = org.bouncycastle.jcajce.PKIXCRLStoreSelector;
	using PKIXCertStore = org.bouncycastle.jcajce.PKIXCertStore;
	using PKIXCertStoreSelector = org.bouncycastle.jcajce.PKIXCertStoreSelector;
	using PKIXExtendedParameters = org.bouncycastle.jcajce.PKIXExtendedParameters;
	using JcaJceHelper = org.bouncycastle.jcajce.util.JcaJceHelper;
	using ExtCertPathValidatorException = org.bouncycastle.jce.exception.ExtCertPathValidatorException;
	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;
	using StoreException = org.bouncycastle.util.StoreException;
	using X509AttributeCertificate = org.bouncycastle.x509.X509AttributeCertificate;
	using X509ExtensionUtil = org.bouncycastle.x509.extension.X509ExtensionUtil;

	public class CertPathValidatorUtilities
	{
		protected internal static readonly PKIXCRLUtil CRL_UTIL = new PKIXCRLUtil();

		protected internal static readonly string CERTIFICATE_POLICIES = Extension.certificatePolicies.getId();
		protected internal static readonly string BASIC_CONSTRAINTS = Extension.basicConstraints.getId();
		protected internal static readonly string POLICY_MAPPINGS = Extension.policyMappings.getId();
		protected internal static readonly string SUBJECT_ALTERNATIVE_NAME = Extension.subjectAlternativeName.getId();
		protected internal static readonly string NAME_CONSTRAINTS = Extension.nameConstraints.getId();
		protected internal static readonly string KEY_USAGE = Extension.keyUsage.getId();
		protected internal static readonly string INHIBIT_ANY_POLICY = Extension.inhibitAnyPolicy.getId();
		protected internal static readonly string ISSUING_DISTRIBUTION_POINT = Extension.issuingDistributionPoint.getId();
		protected internal static readonly string DELTA_CRL_INDICATOR = Extension.deltaCRLIndicator.getId();
		protected internal static readonly string POLICY_CONSTRAINTS = Extension.policyConstraints.getId();
		protected internal static readonly string FRESHEST_CRL = Extension.freshestCRL.getId();
		protected internal static readonly string CRL_DISTRIBUTION_POINTS = Extension.cRLDistributionPoints.getId();
		protected internal static readonly string AUTHORITY_KEY_IDENTIFIER = Extension.authorityKeyIdentifier.getId();

		protected internal const string ANY_POLICY = "2.5.29.32.0";

		protected internal static readonly string CRL_NUMBER = Extension.cRLNumber.getId();

		/*
		* key usage bits
		*/
		protected internal const int KEY_CERT_SIGN = 5;
		protected internal const int CRL_SIGN = 6;

		protected internal static readonly string[] crlReasons = new string[]{"unspecified", "keyCompromise", "cACompromise", "affiliationChanged", "superseded", "cessationOfOperation", "certificateHold", "unknown", "removeFromCRL", "privilegeWithdrawn", "aACompromise"};

		/// <summary>
		/// Search the given Set of TrustAnchor's for one that is the
		/// issuer of the given X509 certificate. Uses the default provider
		/// for signature verification.
		/// </summary>
		/// <param name="cert">         the X509 certificate </param>
		/// <param name="trustAnchors"> a Set of TrustAnchor's </param>
		/// <returns> the <code>TrustAnchor</code> object if found or
		///         <code>null</code> if not. </returns>
		/// <exception cref="AnnotatedException"> if a TrustAnchor was found but the signature verification
		/// on the given certificate has thrown an exception. </exception>
		protected internal static TrustAnchor findTrustAnchor(X509Certificate cert, Set trustAnchors)
		{
			return findTrustAnchor(cert, trustAnchors, null);
		}

		/// <summary>
		/// Search the given Set of TrustAnchor's for one that is the
		/// issuer of the given X509 certificate. Uses the specified
		/// provider for signature verification, or the default provider
		/// if null.
		/// </summary>
		/// <param name="cert">         the X509 certificate </param>
		/// <param name="trustAnchors"> a Set of TrustAnchor's </param>
		/// <param name="sigProvider">  the provider to use for signature verification </param>
		/// <returns> the <code>TrustAnchor</code> object if found or
		///         <code>null</code> if not. </returns>
		/// <exception cref="AnnotatedException"> if a TrustAnchor was found but the signature verification
		/// on the given certificate has thrown an exception. </exception>
		protected internal static TrustAnchor findTrustAnchor(X509Certificate cert, Set trustAnchors, string sigProvider)
		{
			TrustAnchor trust = null;
			PublicKey trustPublicKey = null;
			Exception invalidKeyEx = null;

			X509CertSelector certSelectX509 = new X509CertSelector();
			X500Name certIssuer = PrincipalUtils.getEncodedIssuerPrincipal(cert);

			try
			{
				certSelectX509.setSubject(certIssuer.getEncoded());
			}
			catch (IOException ex)
			{
				throw new AnnotatedException("Cannot set subject search criteria for trust anchor.", ex);
			}

			Iterator iter = trustAnchors.iterator();
			while (iter.hasNext() && trust == null)
			{
				trust = (TrustAnchor)iter.next();
				if (trust.getTrustedCert() != null)
				{
					if (certSelectX509.match(trust.getTrustedCert()))
					{
						trustPublicKey = trust.getTrustedCert().getPublicKey();
					}
					else
					{
						trust = null;
					}
				}
				else if (trust.getCAName() != null && trust.getCAPublicKey() != null)
				{
					try
					{
						X500Name caName = PrincipalUtils.getCA(trust);
						if (certIssuer.Equals(caName))
						{
							trustPublicKey = trust.getCAPublicKey();
						}
						else
						{
							trust = null;
						}
					}
					catch (IllegalArgumentException)
					{
						trust = null;
					}
				}
				else
				{
					trust = null;
				}

				if (trustPublicKey != null)
				{
					try
					{
						verifyX509Certificate(cert, trustPublicKey, sigProvider);
					}
					catch (Exception ex)
					{
						invalidKeyEx = ex;
						trust = null;
						trustPublicKey = null;
					}
				}
			}

			if (trust == null && invalidKeyEx != null)
			{
				throw new AnnotatedException("TrustAnchor found but certificate validation failed.", invalidKeyEx);
			}

			return trust;
		}

		internal static bool isIssuerTrustAnchor(X509Certificate cert, Set trustAnchors, string sigProvider)
		{
			try
			{
				return findTrustAnchor(cert, trustAnchors, sigProvider) != null;
			}
			catch (Exception)
			{
				return false;
			}
		}

		internal static List<PKIXCertStore> getAdditionalStoresFromAltNames(byte[] issuerAlternativeName, Map<GeneralName, PKIXCertStore> altNameCertStoreMap)
		{
			// if in the IssuerAltName extension an URI
			// is given, add an additional X.509 store
			if (issuerAlternativeName != null)
			{
				GeneralNames issuerAltName = GeneralNames.getInstance(ASN1OctetString.getInstance(issuerAlternativeName).getOctets());

				GeneralName[] names = issuerAltName.getNames();
				List<PKIXCertStore> stores = new ArrayList<PKIXCertStore>();

				for (int i = 0; i != names.Length; i++)
				{
					GeneralName altName = names[i];

					PKIXCertStore altStore = altNameCertStoreMap.get(altName);

					if (altStore != null)
					{
						stores.add(altStore);
					}
				}

				return stores;
			}
			else
			{
				return Collections.EMPTY_LIST;
			}
		}

		protected internal static DateTime getValidDate(PKIXExtendedParameters paramsPKIX)
		{
			DateTime validDate = paramsPKIX.getDate();

			if (validDate == null)
			{
				validDate = DateTime.Now;
			}

			return validDate;
		}

		protected internal static bool isSelfIssued(X509Certificate cert)
		{
			return cert.getSubjectDN().Equals(cert.getIssuerDN());
		}


		/// <summary>
		/// Extract the value of the given extension, if it exists.
		/// </summary>
		/// <param name="ext"> The extension object. </param>
		/// <param name="oid"> The object identifier to obtain. </param>
		/// <exception cref="AnnotatedException"> if the extension cannot be read. </exception>
		protected internal static ASN1Primitive getExtensionValue(java.security.cert.X509Extension ext, string oid)
		{
			byte[] bytes = ext.getExtensionValue(oid);
			if (bytes == null)
			{
				return null;
			}

			return getObject(oid, bytes);
		}

		private static ASN1Primitive getObject(string oid, byte[] ext)
		{
			try
			{
				ASN1InputStream aIn = new ASN1InputStream(ext);
				ASN1OctetString octs = (ASN1OctetString)aIn.readObject();

				aIn = new ASN1InputStream(octs.getOctets());
				return aIn.readObject();
			}
			catch (Exception e)
			{
				throw new AnnotatedException("exception processing extension " + oid, e);
			}
		}

		protected internal static AlgorithmIdentifier getAlgorithmIdentifier(PublicKey key)
		{
			try
			{
				ASN1InputStream aIn = new ASN1InputStream(key.getEncoded());

				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(aIn.readObject());

				return info.getAlgorithm();
			}
			catch (Exception e)
			{
				throw new ExtCertPathValidatorException("Subject public key cannot be decoded.", e);
			}
		}

		// crl checking


		//
		// policy checking
		// 

		protected internal static Set getQualifierSet(ASN1Sequence qualifiers)
		{
			Set pq = new HashSet();

			if (qualifiers == null)
			{
				return pq;
			}

			ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			ASN1OutputStream aOut = new ASN1OutputStream(bOut);

			Enumeration e = qualifiers.getObjects();

			while (e.hasMoreElements())
			{
				try
				{
					aOut.writeObject((ASN1Encodable)e.nextElement());

					pq.add(new PolicyQualifierInfo(bOut.toByteArray()));
				}
				catch (IOException ex)
				{
					throw new ExtCertPathValidatorException("Policy qualifier info cannot be decoded.", ex);
				}

				bOut.reset();
			}

			return pq;
		}

		protected internal static PKIXPolicyNode removePolicyNode(PKIXPolicyNode validPolicyTree, List[] policyNodes, PKIXPolicyNode _node)
		{
			PKIXPolicyNode _parent = (PKIXPolicyNode)_node.getParent();

			if (validPolicyTree == null)
			{
				return null;
			}

			if (_parent == null)
			{
				for (int j = 0; j < policyNodes.Length; j++)
				{
					policyNodes[j] = new ArrayList();
				}

				return null;
			}
			else
			{
				_parent.removeChild(_node);
				removePolicyNodeRecurse(policyNodes, _node);

				return validPolicyTree;
			}
		}

		private static void removePolicyNodeRecurse(List[] policyNodes, PKIXPolicyNode _node)
		{
			policyNodes[_node.getDepth()].remove(_node);

			if (_node.hasChildren())
			{
				Iterator _iter = _node.getChildren();
				while (_iter.hasNext())
				{
					PKIXPolicyNode _child = (PKIXPolicyNode)_iter.next();
					removePolicyNodeRecurse(policyNodes, _child);
				}
			}
		}


		protected internal static bool processCertD1i(int index, List[] policyNodes, ASN1ObjectIdentifier pOid, Set pq)
		{
			List policyNodeVec = policyNodes[index - 1];

			for (int j = 0; j < policyNodeVec.size(); j++)
			{
				PKIXPolicyNode node = (PKIXPolicyNode)policyNodeVec.get(j);
				Set expectedPolicies = node.getExpectedPolicies();

				if (expectedPolicies.contains(pOid.getId()))
				{
					Set childExpectedPolicies = new HashSet();
					childExpectedPolicies.add(pOid.getId());

					PKIXPolicyNode child = new PKIXPolicyNode(new ArrayList(), index, childExpectedPolicies, node, pq, pOid.getId(), false);
					node.addChild(child);
					policyNodes[index].add(child);

					return true;
				}
			}

			return false;
		}

		protected internal static void processCertD1ii(int index, List[] policyNodes, ASN1ObjectIdentifier _poid, Set _pq)
		{
			List policyNodeVec = policyNodes[index - 1];

			for (int j = 0; j < policyNodeVec.size(); j++)
			{
				PKIXPolicyNode _node = (PKIXPolicyNode)policyNodeVec.get(j);

				if (ANY_POLICY.Equals(_node.getValidPolicy()))
				{
					Set _childExpectedPolicies = new HashSet();
					_childExpectedPolicies.add(_poid.getId());

					PKIXPolicyNode _child = new PKIXPolicyNode(new ArrayList(), index, _childExpectedPolicies, _node, _pq, _poid.getId(), false);
					_node.addChild(_child);
					policyNodes[index].add(_child);
					return;
				}
			}
		}

		protected internal static void prepareNextCertB1(int i, List[] policyNodes, string id_p, Map m_idp, X509Certificate cert)
		{
			bool idp_found = false;
			Iterator nodes_i = policyNodes[i].iterator();
			while (nodes_i.hasNext())
			{
				PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
				if (node.getValidPolicy().Equals(id_p))
				{
					idp_found = true;
					node.expectedPolicies = (Set)m_idp.get(id_p);
					break;
				}
			}

			if (!idp_found)
			{
				nodes_i = policyNodes[i].iterator();
				while (nodes_i.hasNext())
				{
					PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
					if (ANY_POLICY.Equals(node.getValidPolicy()))
					{
						Set pq = null;
						ASN1Sequence policies = null;
						try
						{
							policies = DERSequence.getInstance(getExtensionValue(cert, CERTIFICATE_POLICIES));
						}
						catch (Exception e)
						{
							throw new AnnotatedException("Certificate policies cannot be decoded.", e);
						}
						Enumeration e = policies.getObjects();
						while (e.hasMoreElements())
						{
							PolicyInformation pinfo = null;

							try
							{
								pinfo = PolicyInformation.getInstance(e.nextElement());
							}
							catch (Exception ex)
							{
								throw new AnnotatedException("Policy information cannot be decoded.", ex);
							}
							if (ANY_POLICY.Equals(pinfo.getPolicyIdentifier().getId()))
							{
								try
								{
									pq = getQualifierSet(pinfo.getPolicyQualifiers());
								}
								catch (CertPathValidatorException ex)
								{
									throw new ExtCertPathValidatorException("Policy qualifier info set could not be built.", ex);
								}
								break;
							}
						}
						bool ci = false;
						if (cert.getCriticalExtensionOIDs() != null)
						{
							ci = cert.getCriticalExtensionOIDs().contains(CERTIFICATE_POLICIES);
						}

						PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
						if (ANY_POLICY.Equals(p_node.getValidPolicy()))
						{
							PKIXPolicyNode c_node = new PKIXPolicyNode(new ArrayList(), i, (Set)m_idp.get(id_p), p_node, pq, id_p, ci);
							p_node.addChild(c_node);
							policyNodes[i].add(c_node);
						}
						break;
					}
				}
			}
		}

		protected internal static PKIXPolicyNode prepareNextCertB2(int i, List[] policyNodes, string id_p, PKIXPolicyNode validPolicyTree)
		{
			Iterator nodes_i = policyNodes[i].iterator();
			while (nodes_i.hasNext())
			{
				PKIXPolicyNode node = (PKIXPolicyNode)nodes_i.next();
				if (node.getValidPolicy().Equals(id_p))
				{
					PKIXPolicyNode p_node = (PKIXPolicyNode)node.getParent();
					p_node.removeChild(node);
					nodes_i.remove();
					for (int k = (i - 1); k >= 0; k--)
					{
						List nodes = policyNodes[k];
						for (int l = 0; l < nodes.size(); l++)
						{
							PKIXPolicyNode node2 = (PKIXPolicyNode)nodes.get(l);
							if (!node2.hasChildren())
							{
								validPolicyTree = removePolicyNode(validPolicyTree, policyNodes, node2);
								if (validPolicyTree == null)
								{
									break;
								}
							}
						}
					}
				}
			}
			return validPolicyTree;
		}

		protected internal static bool isAnyPolicy(Set policySet)
		{
			return policySet == null || policySet.contains(ANY_POLICY) || policySet.isEmpty();
		}

		/// <summary>
		/// Return a Collection of all certificates or attribute certificates found
		/// in the X509Store's that are matching the certSelect criteriums.
		/// </summary>
		/// <param name="certSelect"> a <seealso cref="Selector"/> object that will be used to select
		///                   the certificates </param>
		/// <param name="certStores"> a List containing only <seealso cref="Store"/> objects. These
		///                   are used to search for certificates. </param>
		/// <returns> a Collection of all found <seealso cref="X509Certificate"/>
		///         May be empty but never <code>null</code>. </returns>
		protected internal static Collection findCertificates(PKIXCertStoreSelector certSelect, List certStores)
		{
			Set certs = new LinkedHashSet();
			Iterator iter = certStores.iterator();

			while (iter.hasNext())
			{
				object obj = iter.next();

				if (obj is Store)
				{
					Store certStore = (Store)obj;
					try
					{
						certs.addAll(certStore.getMatches(certSelect));
					}
					catch (StoreException e)
					{
						throw new AnnotatedException("Problem while picking certificates from X.509 store.", e);
					}
				}
				else
				{
					CertStore certStore = (CertStore)obj;

					try
					{
						certs.addAll(PKIXCertStoreSelector.getCertificates(certSelect, certStore));
					}
					catch (CertStoreException e)
					{
						throw new AnnotatedException("Problem while picking certificates from certificate store.", e);
					}
				}
			}
			return certs;
		}

		internal static List<PKIXCRLStore> getAdditionalStoresFromCRLDistributionPoint(CRLDistPoint crldp, Map<GeneralName, PKIXCRLStore> namedCRLStoreMap)
		{
			if (crldp != null)
			{
				DistributionPoint[] dps = null;
				try
				{
					dps = crldp.getDistributionPoints();
				}
				catch (Exception e)
				{
					throw new AnnotatedException("Distribution points could not be read.", e);
				}
				List<PKIXCRLStore> stores = new ArrayList<PKIXCRLStore>();

				for (int i = 0; i < dps.Length; i++)
				{
					DistributionPointName dpn = dps[i].getDistributionPoint();
					// look for URIs in fullName
					if (dpn != null)
					{
						if (dpn.getType() == DistributionPointName.FULL_NAME)
						{
							GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();

							for (int j = 0; j < genNames.Length; j++)
							{
								PKIXCRLStore store = namedCRLStoreMap.get(genNames[j]);
								if (store != null)
								{
									stores.add(store);
								}
							}
						}
					}
				}

				return stores;
			}
			else
			{
				return Collections.EMPTY_LIST;
			}
		}

		/// <summary>
		/// Add the CRL issuers from the cRLIssuer field of the distribution point or
		/// from the certificate if not given to the issuer criterion of the
		/// <code>selector</code>.
		/// <para>
		/// The <code>issuerPrincipals</code> are a collection with a single
		/// <code>X500Name</code> for <code>X509Certificate</code>s.
		/// </para> </summary>
		/// <param name="dp">               The distribution point. </param>
		/// <param name="issuerPrincipals"> The issuers of the certificate or attribute
		///                         certificate which contains the distribution point. </param>
		/// <param name="selector">         The CRL selector. </param>
		/// <exception cref="AnnotatedException"> if an exception occurs while processing. </exception>
		/// <exception cref="ClassCastException"> if <code>issuerPrincipals</code> does not
		/// contain only <code>X500Name</code>s. </exception>
		protected internal static void getCRLIssuersFromDistributionPoint(DistributionPoint dp, Collection issuerPrincipals, X509CRLSelector selector)
		{
			List issuers = new ArrayList();
			// indirect CRL
			if (dp.getCRLIssuer() != null)
			{
				GeneralName[] genNames = dp.getCRLIssuer().getNames();
				// look for a DN
				for (int j = 0; j < genNames.Length; j++)
				{
					if (genNames[j].getTagNo() == GeneralName.directoryName)
					{
						try
						{
							issuers.add(X500Name.getInstance(genNames[j].getName().toASN1Primitive().getEncoded()));
						}
						catch (IOException e)
						{
							throw new AnnotatedException("CRL issuer information from distribution point cannot be decoded.", e);
						}
					}
				}
			}
			else
			{
				/*
				 * certificate issuer is CRL issuer, distributionPoint field MUST be
				 * present.
				 */
				if (dp.getDistributionPoint() == null)
				{
					throw new AnnotatedException("CRL issuer is omitted from distribution point but no distributionPoint field present.");
				}
				// add and check issuer principals
				for (Iterator it = issuerPrincipals.iterator(); it.hasNext();)
				{
					issuers.add(it.next());
				}
			}
			// TODO: is not found although this should correctly add the rel name. selector of Sun is buggy here or PKI test case is invalid
			// distributionPoint
	//        if (dp.getDistributionPoint() != null)
	//        {
	//            // look for nameRelativeToCRLIssuer
	//            if (dp.getDistributionPoint().getType() == DistributionPointName.NAME_RELATIVE_TO_CRL_ISSUER)
	//            {
	//                // append fragment to issuer, only one
	//                // issuer can be there, if this is given
	//                if (issuers.size() != 1)
	//                {
	//                    throw new AnnotatedException(
	//                        "nameRelativeToCRLIssuer field is given but more than one CRL issuer is given.");
	//                }
	//                ASN1Encodable relName = dp.getDistributionPoint().getName();
	//                Iterator it = issuers.iterator();
	//                List issuersTemp = new ArrayList(issuers.size());
	//                while (it.hasNext())
	//                {
	//                    Enumeration e = null;
	//                    try
	//                    {
	//                        e = ASN1Sequence.getInstance(
	//                            new ASN1InputStream(((X500Principal) it.next())
	//                                .getEncoded()).readObject()).getObjects();
	//                    }
	//                    catch (IOException ex)
	//                    {
	//                        throw new AnnotatedException(
	//                            "Cannot decode CRL issuer information.", ex);
	//                    }
	//                    ASN1EncodableVector v = new ASN1EncodableVector();
	//                    while (e.hasMoreElements())
	//                    {
	//                        v.add((ASN1Encodable) e.nextElement());
	//                    }
	//                    v.add(relName);
	//                    issuersTemp.add(new X500Principal(new DERSequence(v)
	//                        .getDEREncoded()));
	//                }
	//                issuers.clear();
	//                issuers.addAll(issuersTemp);
	//            }
	//        }
			Iterator it = issuers.iterator();
			while (it.hasNext())
			{
				try
				{
					selector.addIssuerName(((X500Name)it.next()).getEncoded());
				}
				catch (IOException ex)
				{
					throw new AnnotatedException("Cannot decode CRL issuer information.", ex);
				}
			}
		}

		private static BigInteger getSerialNumber(object cert)
		{
			return ((X509Certificate)cert).getSerialNumber();
		}

		protected internal static void getCertStatus(DateTime validDate, X509CRL crl, object cert, CertStatus certStatus)
		{
			X509CRLEntry crl_entry = null;

			bool isIndirect;
			try
			{
				isIndirect = X509CRLObject.isIndirectCRL(crl);
			}
			catch (CRLException exception)
			{
				throw new AnnotatedException("Failed check for indirect CRL.", exception);
			}

			if (isIndirect)
			{
				crl_entry = crl.getRevokedCertificate(getSerialNumber(cert));

				if (crl_entry == null)
				{
					return;
				}

				X500Principal certificateIssuer = crl_entry.getCertificateIssuer();

				X500Name certIssuer;
				if (certificateIssuer == null)
				{
					certIssuer = PrincipalUtils.getIssuerPrincipal(crl);
				}
				else
				{
					certIssuer = X500Name.getInstance(certificateIssuer.getEncoded());
				}

				if (!PrincipalUtils.getEncodedIssuerPrincipal(cert).Equals(certIssuer))
				{
					return;
				}
			}
			else if (!PrincipalUtils.getEncodedIssuerPrincipal(cert).Equals(PrincipalUtils.getIssuerPrincipal(crl)))
			{
				return; // not for our issuer, ignore
			}
			else
			{
				crl_entry = crl.getRevokedCertificate(getSerialNumber(cert));

				if (crl_entry == null)
				{
					return;
				}
			}

			ASN1Enumerated reasonCode = null;
			if (crl_entry.hasExtensions())
			{
				try
				{
					reasonCode = ASN1Enumerated.getInstance(CertPathValidatorUtilities.getExtensionValue(crl_entry, Extension.reasonCode.getId()));
				}
				catch (Exception e)
				{
					throw new AnnotatedException("Reason code CRL entry extension could not be decoded.", e);
				}
			}

			// for reason keyCompromise, caCompromise, aACompromise or
			// unspecified
			if (!(validDate.Ticks < crl_entry.getRevocationDate().getTime()) || reasonCode == null || reasonCode.getValue().intValue() == 0 || reasonCode.getValue().intValue() == 1 || reasonCode.getValue().intValue() == 2 || reasonCode.getValue().intValue() == 8)
			{

				// (i) or (j) (1)
				if (reasonCode != null)
				{
					certStatus.setCertStatus(reasonCode.getValue().intValue());
				}
				// (i) or (j) (2)
				else
				{
					certStatus.setCertStatus(CRLReason.unspecified);
				}
				certStatus.setRevocationDate(crl_entry.getRevocationDate());
			}
		}

		/// <summary>
		/// Fetches delta CRLs according to RFC 3280 section 5.2.4.
		/// </summary>
		/// <param name="validityDate"> The date for which the delta CRLs must be valid. </param>
		/// <param name="completeCRL"> The complete CRL the delta CRL is for. </param>
		/// <returns> A <code>Set</code> of <code>X509CRL</code>s with delta CRLs. </returns>
		/// <exception cref="AnnotatedException"> if an exception occurs while picking the delta
		/// CRLs. </exception>
		protected internal static Set getDeltaCRLs(DateTime validityDate, X509CRL completeCRL, List<CertStore> certStores, List<PKIXCRLStore> pkixCrlStores)
		{
			X509CRLSelector baseDeltaSelect = new X509CRLSelector();
			// 5.2.4 (a)
			try
			{
				baseDeltaSelect.addIssuerName(PrincipalUtils.getIssuerPrincipal(completeCRL).getEncoded());
			}
			catch (IOException e)
			{
				throw new AnnotatedException("Cannot extract issuer from CRL.", e);
			}



			BigInteger completeCRLNumber = null;
			try
			{
				ASN1Primitive derObject = CertPathValidatorUtilities.getExtensionValue(completeCRL, CRL_NUMBER);
				if (derObject != null)
				{
					completeCRLNumber = ASN1Integer.getInstance(derObject).getPositiveValue();
				}
			}
			catch (Exception e)
			{
				throw new AnnotatedException("CRL number extension could not be extracted from CRL.", e);
			}

			// 5.2.4 (b)
			byte[] idp = null;
			try
			{
				idp = completeCRL.getExtensionValue(ISSUING_DISTRIBUTION_POINT);
			}
			catch (Exception e)
			{
				throw new AnnotatedException("Issuing distribution point extension value could not be read.", e);
			}

			// 5.2.4 (d)

			baseDeltaSelect.setMinCRLNumber(completeCRLNumber == null ? null : completeCRLNumber.add(BigInteger.valueOf(1)));

			PKIXCRLStoreSelector.Builder selBuilder = new PKIXCRLStoreSelector.Builder(baseDeltaSelect);

			selBuilder.setIssuingDistributionPoint(idp);
			selBuilder.setIssuingDistributionPointEnabled(true);

			// 5.2.4 (c)
			selBuilder.setMaxBaseCRLNumber(completeCRLNumber);

			PKIXCRLStoreSelector deltaSelect = selBuilder.build();

			// find delta CRLs
			Set temp = CRL_UTIL.findCRLs(deltaSelect, validityDate, certStores, pkixCrlStores);

			Set result = new HashSet();

			for (Iterator it = temp.iterator(); it.hasNext();)
			{
				X509CRL crl = (X509CRL)it.next();

				if (isDeltaCRL(crl))
				{
					result.add(crl);
				}
			}

			return result;
		}

		private static bool isDeltaCRL(X509CRL crl)
		{
			Set critical = crl.getCriticalExtensionOIDs();

			if (critical == null)
			{
				return false;
			}

			return critical.contains(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);
		}

		/// <summary>
		/// Fetches complete CRLs according to RFC 3280.
		/// </summary>
		/// <param name="dp">          The distribution point for which the complete CRL </param>
		/// <param name="cert">        The <code>X509Certificate</code> for
		///                    which the CRL should be searched. </param>
		/// <param name="currentDate"> The date for which the delta CRLs must be valid. </param>
		/// <param name="paramsPKIX">  The extended PKIX parameters. </param>
		/// <returns> A <code>Set</code> of <code>X509CRL</code>s with complete
		///         CRLs. </returns>
		/// <exception cref="AnnotatedException"> if an exception occurs while picking the CRLs
		/// or no CRLs are found. </exception>
		protected internal static Set getCompleteCRLs(DistributionPoint dp, object cert, DateTime currentDate, PKIXExtendedParameters paramsPKIX)
		{
			X509CRLSelector baseCrlSelect = new X509CRLSelector();

			try
			{
				Set issuers = new HashSet();

				issuers.add(PrincipalUtils.getEncodedIssuerPrincipal(cert));

				CertPathValidatorUtilities.getCRLIssuersFromDistributionPoint(dp, issuers, baseCrlSelect);
			}
			catch (AnnotatedException e)
			{
				throw new AnnotatedException("Could not get issuer information from distribution point.", e);
			}

			if (cert is X509Certificate)
			{
				baseCrlSelect.setCertificateChecking((X509Certificate)cert);
			}

			PKIXCRLStoreSelector crlSelect = (new PKIXCRLStoreSelector.Builder(baseCrlSelect)).setCompleteCRLEnabled(true).build();

			DateTime validityDate = currentDate;

			if (paramsPKIX.getDate() != null)
			{
				validityDate = paramsPKIX.getDate();
			}

			Set crls = CRL_UTIL.findCRLs(crlSelect, validityDate, paramsPKIX.getCertStores(), paramsPKIX.getCRLStores());

			checkCRLsNotEmpty(crls, cert);

			return crls;
		}

		protected internal static DateTime getValidCertDateFromValidityModel(PKIXExtendedParameters paramsPKIX, CertPath certPath, int index)
		{
			if (paramsPKIX.getValidityModel() == PKIXExtendedParameters.CHAIN_VALIDITY_MODEL)
			{
				// if end cert use given signing/encryption/... time
				if (index <= 0)
				{
					return CertPathValidatorUtilities.getValidDate(paramsPKIX);
					// else use time when previous cert was created
				}
				else
				{
					if (index - 1 == 0)
					{
						ASN1GeneralizedTime dateOfCertgen = null;
						try
						{
							byte[] extBytes = ((X509Certificate)certPath.getCertificates().get(index - 1)).getExtensionValue(ISISMTTObjectIdentifiers_Fields.id_isismtt_at_dateOfCertGen.getId());
							if (extBytes != null)
							{
								dateOfCertgen = ASN1GeneralizedTime.getInstance(ASN1Primitive.fromByteArray(extBytes));
							}
						}
						catch (IOException)
						{
							throw new AnnotatedException("Date of cert gen extension could not be read.");
						}
						catch (IllegalArgumentException)
						{
							throw new AnnotatedException("Date of cert gen extension could not be read.");
						}
						if (dateOfCertgen != null)
						{
							try
							{
								return dateOfCertgen.getDate();
							}
							catch (ParseException e)
							{
								throw new AnnotatedException("Date from date of cert gen extension could not be parsed.", e);
							}
						}
						return ((X509Certificate)certPath.getCertificates().get(index - 1)).getNotBefore();
					}
					else
					{
						return ((X509Certificate)certPath.getCertificates().get(index - 1)).getNotBefore();
					}
				}
			}
			else
			{
				return getValidDate(paramsPKIX);
			}
		}

		/// <summary>
		/// Return the next working key inheriting DSA parameters if necessary.
		/// <para>
		/// This methods inherits DSA parameters from the indexed certificate or
		/// previous certificates in the certificate chain to the returned
		/// <code>PublicKey</code>. The list is searched upwards, meaning the end
		/// certificate is at position 0 and previous certificates are following.
		/// </para>
		/// <para>
		/// If the indexed certificate does not contain a DSA key this method simply
		/// returns the public key. If the DSA key already contains DSA parameters
		/// the key is also only returned.
		/// </para>
		/// </summary>
		/// <param name="certs"> The certification path. </param>
		/// <param name="index"> The index of the certificate which contains the public key
		///              which should be extended with DSA parameters. </param>
		/// <returns> The public key of the certificate in list position
		///         <code>index</code> extended with DSA parameters if applicable. </returns>
		/// <exception cref="AnnotatedException"> if DSA parameters cannot be inherited. </exception>
		protected internal static PublicKey getNextWorkingKey(List certs, int index, JcaJceHelper helper)
		{
			Certificate cert = (Certificate)certs.get(index);
			PublicKey pubKey = cert.getPublicKey();
			if (!(pubKey is DSAPublicKey))
			{
				return pubKey;
			}
			DSAPublicKey dsaPubKey = (DSAPublicKey)pubKey;
			if (dsaPubKey.getParams() != null)
			{
				return dsaPubKey;
			}
			for (int i = index + 1; i < certs.size(); i++)
			{
				X509Certificate parentCert = (X509Certificate)certs.get(i);
				pubKey = parentCert.getPublicKey();
				if (!(pubKey is DSAPublicKey))
				{
					throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
				}
				DSAPublicKey prevDSAPubKey = (DSAPublicKey)pubKey;
				if (prevDSAPubKey.getParams() == null)
				{
					continue;
				}
				DSAParams dsaParams = prevDSAPubKey.getParams();
				DSAPublicKeySpec dsaPubKeySpec = new DSAPublicKeySpec(dsaPubKey.getY(), dsaParams.getP(), dsaParams.getQ(), dsaParams.getG());
				try
				{
					KeyFactory keyFactory = helper.createKeyFactory("DSA");
					return keyFactory.generatePublic(dsaPubKeySpec);
				}
				catch (Exception exception)
				{
					throw new RuntimeException(exception.Message);
				}
			}
			throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
		}

		/// <summary>
		/// Find the issuer certificates of a given certificate.
		/// </summary>
		/// <param name="cert">       The certificate for which an issuer should be found. </param>
		/// <returns> A <code>Collection</code> object containing the issuer
		///         <code>X509Certificate</code>s. Never <code>null</code>. </returns>
		/// <exception cref="AnnotatedException"> if an error occurs. </exception>
		internal static Collection findIssuerCerts(X509Certificate cert, List<CertStore> certStores, List<PKIXCertStore> pkixCertStores)
		{
			X509CertSelector selector = new X509CertSelector();

			try
			{
				selector.setSubject(PrincipalUtils.getIssuerPrincipal(cert).getEncoded());
			}
			catch (IOException e)
			{
				throw new AnnotatedException("Subject criteria for certificate selector to find issuer certificate could not be set.", e);
			}

			try
			{
				byte[] akiExtensionValue = cert.getExtensionValue(AUTHORITY_KEY_IDENTIFIER);
				if (akiExtensionValue != null)
				{
					ASN1OctetString aki = ASN1OctetString.getInstance(akiExtensionValue);
					byte[] authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(aki.getOctets()).getKeyIdentifier();
					if (authorityKeyIdentifier != null)
					{
						selector.setSubjectKeyIdentifier((new DEROctetString(authorityKeyIdentifier)).getEncoded());
					}
				}
			}
			catch (Exception)
			{
				// authority key identifier could not be retrieved from target cert, just search without it
			}

			PKIXCertStoreSelector certSelect = (new PKIXCertStoreSelector.Builder(selector)).build();
			Set certs = new LinkedHashSet();

			Iterator iter;

			try
			{
				List matches = new ArrayList();

				matches.addAll(CertPathValidatorUtilities.findCertificates(certSelect, certStores));
				matches.addAll(CertPathValidatorUtilities.findCertificates(certSelect, pkixCertStores));

				iter = matches.iterator();
			}
			catch (AnnotatedException e)
			{
				throw new AnnotatedException("Issuer certificate cannot be searched.", e);
			}

			X509Certificate issuer = null;
			while (iter.hasNext())
			{
				issuer = (X509Certificate)iter.next();
				// issuer cannot be verified because possible DSA inheritance
				// parameters are missing
				certs.add(issuer);
			}
			return certs;
		}

		protected internal static void verifyX509Certificate(X509Certificate cert, PublicKey publicKey, string sigProvider)
		{
			if (string.ReferenceEquals(sigProvider, null))
			{
				cert.verify(publicKey);
			}
			else
			{
				cert.verify(publicKey, sigProvider);
			}
		}

		internal static void checkCRLsNotEmpty(Set crls, object cert)
		{
			if (crls.isEmpty())
			{
				if (cert is X509AttributeCertificate)
				{
					X509AttributeCertificate aCert = (X509AttributeCertificate)cert;

					throw new AnnotatedException(@"No CRLs found for issuer """ + aCert.getIssuer().getPrincipals()[0] + @"""");
				}
				else
				{
					X509Certificate xCert = (X509Certificate)cert;

					throw new AnnotatedException(@"No CRLs found for issuer """ + RFC4519Style.INSTANCE.ToString(PrincipalUtils.getIssuerPrincipal(xCert)) + @"""");
				}
			}
		}
	}

}