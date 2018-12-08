using org.bouncycastle.jcajce.provider.asymmetric.x509;

using System;

namespace org.bouncycastle.x509
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Enumerated = org.bouncycastle.asn1.ASN1Enumerated;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1OutputStream = org.bouncycastle.asn1.ASN1OutputStream;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using CRLReason = org.bouncycastle.asn1.x509.CRLReason;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using IssuingDistributionPoint = org.bouncycastle.asn1.x509.IssuingDistributionPoint;
	using PolicyInformation = org.bouncycastle.asn1.x509.PolicyInformation;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using X509Extension = org.bouncycastle.asn1.x509.X509Extension;
	using PKIXCertStoreSelector = org.bouncycastle.jcajce.PKIXCertStoreSelector;
	using ExtCertPathValidatorException = org.bouncycastle.jce.exception.ExtCertPathValidatorException;
	using AnnotatedException = org.bouncycastle.jce.provider.AnnotatedException;
	using BouncyCastleProvider = org.bouncycastle.jce.provider.BouncyCastleProvider;
	using PKIXPolicyNode = org.bouncycastle.jce.provider.PKIXPolicyNode;
	using Encodable = org.bouncycastle.util.Encodable;
	using Selector = org.bouncycastle.util.Selector;
	using Store = org.bouncycastle.util.Store;
	using StoreException = org.bouncycastle.util.StoreException;

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
		/// Returns the issuer of an attribute certificate or certificate.
		/// </summary>
		/// <param name="cert"> The attribute certificate or certificate. </param>
		/// <returns> The issuer as <code>X500Principal</code>. </returns>
		protected internal static X500Principal getEncodedIssuerPrincipal(object cert)
		{
			if (cert is X509Certificate)
			{
				return ((X509Certificate)cert).getIssuerX500Principal();
			}
			else
			{
				return (X500Principal)((X509AttributeCertificate)cert).getIssuer().getPrincipals()[0];
			}
		}

		protected internal static DateTime getValidDate(PKIXParameters paramsPKIX)
		{
			DateTime validDate = paramsPKIX.getDate();

			if (validDate == null)
			{
				validDate = DateTime.Now;
			}

			return validDate;
		}

		protected internal static X500Principal getSubjectPrincipal(X509Certificate cert)
		{
			return cert.getSubjectX500Principal();
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

		protected internal static X500Principal getIssuerPrincipal(X509CRL crl)
		{
			return crl.getIssuerX500Principal();
		}

		protected internal static AlgorithmIdentifier getAlgorithmIdentifier(PublicKey key)
		{
			try
			{
				ASN1InputStream aIn = new ASN1InputStream(key.getEncoded());

				SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(aIn.readObject());

				return info.getAlgorithmId();
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
					node.setExpectedPolicies((Set)m_idp.get(id_p));
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
		/// <param name="certStores"> a List containing only <seealso cref="X509Store"/> objects. These
		///                   are used to search for certificates. </param>
		/// <returns> a Collection of all found <seealso cref="X509Certificate"/> or
		///         <seealso cref="org.bouncycastle.x509.X509AttributeCertificate"/> objects.
		///         May be empty but never <code>null</code>. </returns>
		protected internal static Collection findCertificates(X509CertStoreSelector certSelect, List certStores)
		{
			Set certs = new HashSet();
			Iterator iter = certStores.iterator();
			CertificateFactory certFact = new CertificateFactory();

			while (iter.hasNext())
			{
				object obj = iter.next();

				if (obj is Store)
				{
					Store certStore = (Store)obj;
					try
					{
						for (Iterator it = certStore.getMatches(certSelect).iterator(); it.hasNext();)
						{
							object cert = it.next();

							if (cert is Encodable)
							{
								certs.add(certFact.engineGenerateCertificate(new ByteArrayInputStream(((Encodable)cert).getEncoded())));
							}
							else if (cert is Certificate)
							{
								 certs.add(cert);
							}
							else
							{
								throw new AnnotatedException("Unknown object found in certificate store.");
							}
						}
					}
					catch (StoreException e)
					{
						throw new AnnotatedException("Problem while picking certificates from X.509 store.", e);
					}
					catch (IOException e)
					{
						throw new AnnotatedException("Problem while extracting certificates from X.509 store.", e);
					}
					catch (CertificateException e)
					{
						throw new AnnotatedException("Problem while extracting certificates from X.509 store.", e);
					}
				}
				else
				{
					CertStore certStore = (CertStore)obj;

					try
					{
						certs.addAll(certStore.getCertificates(certSelect));
					}
					catch (CertStoreException e)
					{
						throw new AnnotatedException("Problem while picking certificates from certificate store.", e);
					}
				}
			}
			return certs;
		}

		protected internal static Collection findCertificates(PKIXCertStoreSelector certSelect, List certStores)
		{
			Set certs = new HashSet();
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

		protected internal static Collection findCertificates(X509AttributeCertStoreSelector certSelect, List certStores)
		{
			Set certs = new HashSet();
			Iterator iter = certStores.iterator();

			while (iter.hasNext())
			{
				object obj = iter.next();

				if (obj is X509Store)
				{
					X509Store certStore = (X509Store)obj;
					try
					{
						certs.addAll(certStore.getMatches(certSelect));
					}
					catch (StoreException e)
					{
						throw new AnnotatedException("Problem while picking certificates from X.509 store.", e);
					}
				}
			}
			return certs;
		}

		private static BigInteger getSerialNumber(object cert)
		{
			if (cert is X509Certificate)
			{
				return ((X509Certificate)cert).getSerialNumber();
			}
			else
			{
				return ((X509AttributeCertificate)cert).getSerialNumber();
			}
		}

		protected internal static void getCertStatus(DateTime validDate, X509CRL crl, object cert, CertStatus certStatus)
		{
			X509CRLEntry crl_entry = null;

			bool isIndirect;
			try
			{
				isIndirect = isIndirectCRL(crl);
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

				X500Principal certIssuer = crl_entry.getCertificateIssuer();

				if (certIssuer == null)
				{
					certIssuer = getIssuerPrincipal(crl);
				}

				if (!getEncodedIssuerPrincipal(cert).Equals(certIssuer))
				{
					return;
				}
			}
			else if (!getEncodedIssuerPrincipal(cert).Equals(getIssuerPrincipal(crl)))
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
					reasonCode = ASN1Enumerated.getInstance(CertPathValidatorUtilities.getExtensionValue(crl_entry, X509Extension.reasonCode.getId()));
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
		/// <exception cref="CertPathValidatorException"> if DSA parameters cannot be inherited. </exception>
		protected internal static PublicKey getNextWorkingKey(List certs, int index)
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
					KeyFactory keyFactory = KeyFactory.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
					return keyFactory.generatePublic(dsaPubKeySpec);
				}
				catch (Exception exception)
				{
					throw new RuntimeException(exception.Message);
				}
			}
			throw new CertPathValidatorException("DSA parameters cannot be inherited from previous certificate.");
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

		internal static bool isIndirectCRL(X509CRL crl)
		{
			try
			{
				byte[] idp = crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
				return idp != null && IssuingDistributionPoint.getInstance(ASN1OctetString.getInstance(idp).getOctets()).isIndirectCRL();
			}
			catch (Exception e)
			{
				throw new CRLException("Exception reading IssuingDistributionPoint: " + e);
			}
		}
	}

}