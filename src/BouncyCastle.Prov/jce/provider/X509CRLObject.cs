using org.bouncycastle.asn1;
using org.bouncycastle.asn1.x509;

using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1Integer = org.bouncycastle.asn1.ASN1Integer;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Dump = org.bouncycastle.asn1.util.ASN1Dump;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using CRLDistPoint = org.bouncycastle.asn1.x509.CRLDistPoint;
	using CRLNumber = org.bouncycastle.asn1.x509.CRLNumber;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using IssuingDistributionPoint = org.bouncycastle.asn1.x509.IssuingDistributionPoint;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// <summary>
	/// The following extensions are listed in RFC 2459 as relevant to CRLs
	/// 
	/// Authority Key Identifier
	/// Issuer Alternative Name
	/// CRL Number
	/// Delta CRL Indicator (critical)
	/// Issuing Distribution Point (critical) </summary>
	/// @deprecated Do not use this class directly - either use org.bouncycastle.cert (bcpkix) or CertificateFactory. 
	public class X509CRLObject : X509CRL
	{
		private CertificateList c;
		private string sigAlgName;
		private byte[] sigAlgParams;
		private bool isIndirect;
		private bool isHashCodeSet = false;
		private int hashCodeValue;

		public static bool isIndirectCRL(X509CRL crl)
		{
			try
			{
				byte[] idp = crl.getExtensionValue(Extension.issuingDistributionPoint.getId());
				return idp != null && IssuingDistributionPoint.getInstance(ASN1OctetString.getInstance(idp).getOctets()).isIndirectCRL();
			}
			catch (Exception e)
			{
				throw new ExtCRLException("Exception reading IssuingDistributionPoint", e);
			}
		}

		public X509CRLObject(CertificateList c)
		{
			this.c = c;

			try
			{
				this.sigAlgName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());

				if (c.getSignatureAlgorithm().getParameters() != null)
				{
					this.sigAlgParams = ((ASN1Encodable)c.getSignatureAlgorithm().getParameters()).toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER);
				}
				else
				{
					this.sigAlgParams = null;
				}

				this.isIndirect = isIndirectCRL(this);
			}
			catch (Exception e)
			{
				throw new CRLException("CRL contents invalid: " + e);
			}
		}

		/// <summary>
		/// Will return true if any extensions are present and marked
		/// as critical as we currently dont handle any extensions!
		/// </summary>
		public virtual bool hasUnsupportedCriticalExtension()
		{
			Set extns = getCriticalExtensionOIDs();

			if (extns == null)
			{
				return false;
			}

			extns.remove(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT);
			extns.remove(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR);

			return !extns.isEmpty();
		}

		private Set getExtensionOIDs(bool critical)
		{
			if (this.getVersion() == 2)
			{
				Extensions extensions = c.getTBSCertList().getExtensions();

				if (extensions != null)
				{
					Set set = new HashSet();
					Enumeration e = extensions.oids();

					while (e.hasMoreElements())
					{
						ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
						Extension ext = extensions.getExtension(oid);

						if (critical == ext.isCritical())
						{
							set.add(oid.getId());
						}
					}

					return set;
				}
			}

			return null;
		}

		public virtual Set getCriticalExtensionOIDs()
		{
			return getExtensionOIDs(true);
		}

		public virtual Set getNonCriticalExtensionOIDs()
		{
			return getExtensionOIDs(false);
		}

		public virtual byte[] getExtensionValue(string oid)
		{
			Extensions exts = c.getTBSCertList().getExtensions();

			if (exts != null)
			{
				Extension ext = exts.getExtension(new ASN1ObjectIdentifier(oid));

				if (ext != null)
				{
					try
					{
						return ext.getExtnValue().getEncoded();
					}
					catch (Exception e)
					{
						throw new IllegalStateException("error parsing " + e.ToString());
					}
				}
			}

			return null;
		}

		public virtual byte[] getEncoded()
		{
			try
			{
				return c.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException e)
			{
				throw new CRLException(e.ToString());
			}
		}

		public virtual void verify(PublicKey key)
		{
			Signature sig;

			try
			{
				sig = Signature.getInstance(getSigAlgName(), BouncyCastleProvider.PROVIDER_NAME);
			}
			catch (Exception)
			{
				sig = Signature.getInstance(getSigAlgName());
			}

			doVerify(key, sig);
		}

		public virtual void verify(PublicKey key, string sigProvider)
		{
			Signature sig;

			if (!string.ReferenceEquals(sigProvider, null))
			{
				sig = Signature.getInstance(getSigAlgName(), sigProvider);
			}
			else
			{
				sig = Signature.getInstance(getSigAlgName());
			}

			doVerify(key, sig);
		}

		public virtual void verify(PublicKey key, Provider sigProvider)
		{
			Signature sig;

			if (sigProvider != null)
			{
				sig = Signature.getInstance(getSigAlgName(), sigProvider);
			}
			else
			{
				sig = Signature.getInstance(getSigAlgName());
			}

			doVerify(key, sig);
		}

		private void doVerify(PublicKey key, Signature sig)
		{
			if (!c.getSignatureAlgorithm().Equals(c.getTBSCertList().getSignature()))
			{
				throw new CRLException("Signature algorithm on CertificateList does not match TBSCertList.");
			}

			sig.initVerify(key);
			sig.update(this.getTBSCertList());

			if (!sig.verify(this.getSignature()))
			{
				throw new SignatureException("CRL does not verify with supplied public key.");
			}
		}

		public virtual int getVersion()
		{
			return c.getVersionNumber();
		}

		public virtual Principal getIssuerDN()
		{
			return new X509Principal(X500Name.getInstance(c.getIssuer().toASN1Primitive()));
		}

		public virtual X500Principal getIssuerX500Principal()
		{
			try
			{
				return new X500Principal(c.getIssuer().getEncoded());
			}
			catch (IOException)
			{
				throw new IllegalStateException("can't encode issuer DN");
			}
		}

		public virtual DateTime getThisUpdate()
		{
			return c.getThisUpdate().getDate();
		}

		public virtual DateTime getNextUpdate()
		{
			if (c.getNextUpdate() != null)
			{
				return c.getNextUpdate().getDate();
			}

			return null;
		}

		private Set loadCRLEntries()
		{
			Set entrySet = new HashSet();
			Enumeration certs = c.getRevokedCertificateEnumeration();

			X500Name previousCertificateIssuer = null; // the issuer
			while (certs.hasMoreElements())
			{
				TBSCertList.CRLEntry entry = (TBSCertList.CRLEntry)certs.nextElement();
				X509CRLEntryObject crlEntry = new X509CRLEntryObject(entry, isIndirect, previousCertificateIssuer);
				entrySet.add(crlEntry);
				if (isIndirect && entry.hasExtensions())
				{
					Extension currentCaName = entry.getExtensions().getExtension(Extension.certificateIssuer);

					if (currentCaName != null)
					{
						previousCertificateIssuer = X500Name.getInstance(GeneralNames.getInstance(currentCaName.getParsedValue()).getNames()[0].getName());
					}
				}
			}

			return entrySet;
		}

		public virtual X509CRLEntry getRevokedCertificate(BigInteger serialNumber)
		{
			Enumeration certs = c.getRevokedCertificateEnumeration();

			X500Name previousCertificateIssuer = null; // the issuer
			while (certs.hasMoreElements())
			{
				TBSCertList.CRLEntry entry = (TBSCertList.CRLEntry)certs.nextElement();

				if (serialNumber.Equals(entry.getUserCertificate().getValue()))
				{
					return new X509CRLEntryObject(entry, isIndirect, previousCertificateIssuer);
				}

				if (isIndirect && entry.hasExtensions())
				{
					Extension currentCaName = entry.getExtensions().getExtension(Extension.certificateIssuer);

					if (currentCaName != null)
					{
						previousCertificateIssuer = X500Name.getInstance(GeneralNames.getInstance(currentCaName.getParsedValue()).getNames()[0].getName());
					}
				}
			}

			return null;
		}

		public virtual Set getRevokedCertificates()
		{
			Set entrySet = loadCRLEntries();

			if (!entrySet.isEmpty())
			{
				return Collections.unmodifiableSet(entrySet);
			}

			return null;
		}

		public virtual byte[] getTBSCertList()
		{
			try
			{
				return c.getTBSCertList().getEncoded("DER");
			}
			catch (IOException e)
			{
				throw new CRLException(e.ToString());
			}
		}

		public virtual byte[] getSignature()
		{
			return c.getSignature().getOctets();
		}

		public virtual string getSigAlgName()
		{
			return sigAlgName;
		}

		public virtual string getSigAlgOID()
		{
			return c.getSignatureAlgorithm().getAlgorithm().getId();
		}

		public virtual byte[] getSigAlgParams()
		{
			if (sigAlgParams != null)
			{
				byte[] tmp = new byte[sigAlgParams.Length];

				JavaSystem.arraycopy(sigAlgParams, 0, tmp, 0, tmp.Length);

				return tmp;
			}

			return null;
		}

		/// <summary>
		/// Returns a string representation of this CRL.
		/// </summary>
		/// <returns> a string representation of this CRL. </returns>
		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append("              Version: ").append(this.getVersion()).append(nl);
			buf.append("             IssuerDN: ").append(this.getIssuerDN()).append(nl);
			buf.append("          This update: ").append(this.getThisUpdate()).append(nl);
			buf.append("          Next update: ").append(this.getNextUpdate()).append(nl);
			buf.append("  Signature Algorithm: ").append(this.getSigAlgName()).append(nl);

			byte[] sig = this.getSignature();

			buf.append("            Signature: ").append(StringHelper.NewString(Hex.encode(sig, 0, 20))).append(nl);
			for (int i = 20; i < sig.Length; i += 20)
			{
				if (i < sig.Length - 20)
				{
					buf.append("                       ").append(StringHelper.NewString(Hex.encode(sig, i, 20))).append(nl);
				}
				else
				{
					buf.append("                       ").append(StringHelper.NewString(Hex.encode(sig, i, sig.Length - i))).append(nl);
				}
			}

			Extensions extensions = c.getTBSCertList().getExtensions();

			if (extensions != null)
			{
				Enumeration e = extensions.oids();

				if (e.hasMoreElements())
				{
					buf.append("           Extensions: ").append(nl);
				}

				while (e.hasMoreElements())
				{
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier) e.nextElement();
					Extension ext = extensions.getExtension(oid);

					if (ext.getExtnValue() != null)
					{
						byte[] octs = ext.getExtnValue().getOctets();
						ASN1InputStream dIn = new ASN1InputStream(octs);
						buf.append("                       critical(").append(ext.isCritical()).append(") ");
						try
						{
							if (oid.Equals(Extension.cRLNumber))
							{
								buf.append(new CRLNumber(ASN1Integer.getInstance(dIn.readObject()).getPositiveValue())).append(nl);
							}
							else if (oid.Equals(Extension.deltaCRLIndicator))
							{
								buf.append("Base CRL: " + new CRLNumber(ASN1Integer.getInstance(dIn.readObject()).getPositiveValue())).append(nl);
							}
							else if (oid.Equals(Extension.issuingDistributionPoint))
							{
								buf.append(IssuingDistributionPoint.getInstance(dIn.readObject())).append(nl);
							}
							else if (oid.Equals(Extension.cRLDistributionPoints))
							{
								buf.append(CRLDistPoint.getInstance(dIn.readObject())).append(nl);
							}
							else if (oid.Equals(Extension.freshestCRL))
							{
								buf.append(CRLDistPoint.getInstance(dIn.readObject())).append(nl);
							}
							else
							{
								buf.append(oid.getId());
								buf.append(" value = ").append(ASN1Dump.dumpAsString(dIn.readObject())).append(nl);
							}
						}
						catch (Exception)
						{
							buf.append(oid.getId());
							buf.append(" value = ").append("*****").append(nl);
						}
					}
					else
					{
						buf.append(nl);
					}
				}
			}
			Set set = getRevokedCertificates();
			if (set != null)
			{
				Iterator it = set.iterator();
				while (it.hasNext())
				{
					buf.append(it.next());
					buf.append(nl);
				}
			}
			return buf.ToString();
		}

		/// <summary>
		/// Checks whether the given certificate is on this CRL.
		/// </summary>
		/// <param name="cert"> the certificate to check for. </param>
		/// <returns> true if the given certificate is on this CRL,
		/// false otherwise. </returns>
		public virtual bool isRevoked(Certificate cert)
		{
			if (!cert.getType().Equals("X.509"))
			{
				throw new RuntimeException("X.509 CRL used with non X.509 Cert");
			}

			Enumeration certs = c.getRevokedCertificateEnumeration();

			X500Name caName = c.getIssuer();

			if (certs != null)
			{
				BigInteger serial = ((X509Certificate)cert).getSerialNumber();

				while (certs.hasMoreElements())
				{
					TBSCertList.CRLEntry entry = TBSCertList.CRLEntry.getInstance(certs.nextElement());

					if (isIndirect && entry.hasExtensions())
					{
						Extension currentCaName = entry.getExtensions().getExtension(Extension.certificateIssuer);

						if (currentCaName != null)
						{
							caName = X500Name.getInstance(GeneralNames.getInstance(currentCaName.getParsedValue()).getNames()[0].getName());
						}
					}

					if (entry.getUserCertificate().getValue().Equals(serial))
					{
						X500Name issuer;

						if (cert is X509Certificate)
						{
							issuer = X500Name.getInstance(((X509Certificate)cert).getIssuerX500Principal().getEncoded());
						}
						else
						{
							try
							{
								issuer = Certificate.getInstance(cert.getEncoded()).getIssuer();
							}
							catch (CertificateEncodingException)
							{
								throw new RuntimeException("Cannot process certificate");
							}
						}

						if (!caName.Equals(issuer))
						{
							return false;
						}

						return true;
					}
				}
			}

			return false;
		}

		public override bool Equals(object other)
		{
			if (this == other)
			{
				return true;
			}

			if (!(other is X509CRL))
			{
				return false;
			}

			if (other is X509CRLObject)
			{
				X509CRLObject crlObject = (X509CRLObject)other;

				if (isHashCodeSet)
				{
					bool otherIsHashCodeSet = crlObject.isHashCodeSet;
					if (otherIsHashCodeSet)
					{
						if (crlObject.hashCodeValue != hashCodeValue)
						{
							return false;
						}
					}
				}

				return this.c.Equals(crlObject.c);
			}

			return base.Equals(other);
		}

		public override int GetHashCode()
		{
			if (!isHashCodeSet)
			{
				isHashCodeSet = true;
				hashCodeValue = base.GetHashCode();
			}

			return hashCodeValue;
		}
	}


}