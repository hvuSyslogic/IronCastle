using org.bouncycastle.asn1.x509;
using org.bouncycastle.asn1;
using org.bouncycastle.asn1.misc;

using System;

namespace org.bouncycastle.jce.provider
{

	using ASN1BitString = org.bouncycastle.asn1.ASN1BitString;
	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1Encoding = org.bouncycastle.asn1.ASN1Encoding;
	using ASN1InputStream = org.bouncycastle.asn1.ASN1InputStream;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OutputStream = org.bouncycastle.asn1.ASN1OutputStream;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1Sequence = org.bouncycastle.asn1.ASN1Sequence;
	using ASN1String = org.bouncycastle.asn1.ASN1String;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERIA5String = org.bouncycastle.asn1.DERIA5String;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using MiscObjectIdentifiers = org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
	using NetscapeCertType = org.bouncycastle.asn1.misc.NetscapeCertType;
	using NetscapeRevocationURL = org.bouncycastle.asn1.misc.NetscapeRevocationURL;
	using VerisignCzagExtension = org.bouncycastle.asn1.misc.VerisignCzagExtension;
	using ASN1Dump = org.bouncycastle.asn1.util.ASN1Dump;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using RFC4519Style = org.bouncycastle.asn1.x500.style.RFC4519Style;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using BasicConstraints = org.bouncycastle.asn1.x509.BasicConstraints;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using KeyUsage = org.bouncycastle.asn1.x509.KeyUsage;
	using PKCS12BagAttributeCarrierImpl = org.bouncycastle.jcajce.provider.asymmetric.util.PKCS12BagAttributeCarrierImpl;
	using PKCS12BagAttributeCarrier = org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
	using Arrays = org.bouncycastle.util.Arrays;
	using Integers = org.bouncycastle.util.Integers;
	using Strings = org.bouncycastle.util.Strings;
	using Hex = org.bouncycastle.util.encoders.Hex;

	/// @deprecated Do not use this class directly - either use org.bouncycastle.cert (bcpkix) or CertificateFactory. 
	public class X509CertificateObject : X509Certificate, PKCS12BagAttributeCarrier
	{
		private Certificate c;
		private BasicConstraints basicConstraints;
		private bool[] keyUsage;
		private bool hashValueSet;
		private int hashValue;

		private PKCS12BagAttributeCarrier attrCarrier = new PKCS12BagAttributeCarrierImpl();

		public X509CertificateObject(Certificate c)
		{
			this.c = c;

			try
			{
				byte[] bytes = this.getExtensionBytes("2.5.29.19");

				if (bytes != null)
				{
					basicConstraints = BasicConstraints.getInstance(ASN1Primitive.fromByteArray(bytes));
				}
			}
			catch (Exception e)
			{
				throw new CertificateParsingException("cannot construct BasicConstraints: " + e);
			}

			try
			{
				byte[] bytes = this.getExtensionBytes("2.5.29.15");
				if (bytes != null)
				{
					ASN1BitString bits = DERBitString.getInstance(ASN1Primitive.fromByteArray(bytes));

					bytes = bits.getBytes();
					int length = (bytes.Length * 8) - bits.getPadBits();

					keyUsage = new bool[(length < 9) ? 9 : length];

					for (int i = 0; i != length; i++)
					{
						keyUsage[i] = (bytes[i / 8] & ((int)((uint)0x80 >> (i % 8)))) != 0;
					}
				}
				else
				{
					keyUsage = null;
				}
			}
			catch (Exception e)
			{
				throw new CertificateParsingException("cannot construct KeyUsage: " + e);
			}
		}

		public virtual void checkValidity()
		{
			this.checkValidity(DateTime.Now);
		}

		public virtual void checkValidity(DateTime date)
		{
			if (date.Ticks > this.getNotAfter().Ticks) // for other VM compatibility
			{
				throw new CertificateExpiredException("certificate expired on " + c.getEndDate().getTime());
			}

			if (date.Ticks < this.getNotBefore().Ticks)
			{
				throw new CertificateNotYetValidException("certificate not valid till " + c.getStartDate().getTime());
			}
		}

		public virtual int getVersion()
		{
			return c.getVersionNumber();
		}

		public virtual BigInteger getSerialNumber()
		{
			return c.getSerialNumber().getValue();
		}

		public virtual Principal getIssuerDN()
		{
			try
			{
				return new X509Principal(X500Name.getInstance(c.getIssuer().getEncoded()));
			}
			catch (IOException)
			{
				return null;
			}
		}

		public virtual X500Principal getIssuerX500Principal()
		{
			try
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				ASN1OutputStream aOut = new ASN1OutputStream(bOut);

				aOut.writeObject(c.getIssuer());

				return new X500Principal(bOut.toByteArray());
			}
			catch (IOException)
			{
				throw new IllegalStateException("can't encode issuer DN");
			}
		}

		public virtual Principal getSubjectDN()
		{
			return new X509Principal(X500Name.getInstance(c.getSubject().toASN1Primitive()));
		}

		public virtual X500Principal getSubjectX500Principal()
		{
			try
			{
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				ASN1OutputStream aOut = new ASN1OutputStream(bOut);

				aOut.writeObject(c.getSubject());

				return new X500Principal(bOut.toByteArray());
			}
			catch (IOException)
			{
				throw new IllegalStateException("can't encode issuer DN");
			}
		}

		public virtual DateTime getNotBefore()
		{
			return c.getStartDate().getDate();
		}

		public virtual DateTime getNotAfter()
		{
			return c.getEndDate().getDate();
		}

		public virtual byte[] getTBSCertificate()
		{
			try
			{
				return c.getTBSCertificate().getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException e)
			{
				throw new CertificateEncodingException(e.ToString());
			}
		}

		public virtual byte[] getSignature()
		{
			return c.getSignature().getOctets();
		}

		/// <summary>
		/// return a more "meaningful" representation for the signature algorithm used in
		/// the certficate.
		/// </summary>
		public virtual string getSigAlgName()
		{
			Provider prov = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);

			if (prov != null)
			{
				string algName = prov.getProperty("Alg.Alias.Signature." + this.getSigAlgOID());

				if (!string.ReferenceEquals(algName, null))
				{
					return algName;
				}
			}

			Provider[] provs = Security.getProviders();

			//
			// search every provider looking for a real algorithm
			//
			for (int i = 0; i != provs.Length; i++)
			{
				string algName = provs[i].getProperty("Alg.Alias.Signature." + this.getSigAlgOID());
				if (!string.ReferenceEquals(algName, null))
				{
					return algName;
				}
			}

			return this.getSigAlgOID();
		}

		/// <summary>
		/// return the object identifier for the signature.
		/// </summary>
		public virtual string getSigAlgOID()
		{
			return c.getSignatureAlgorithm().getAlgorithm().getId();
		}

		/// <summary>
		/// return the signature parameters, or null if there aren't any.
		/// </summary>
		public virtual byte[] getSigAlgParams()
		{
			if (c.getSignatureAlgorithm().getParameters() != null)
			{
				try
				{
					return c.getSignatureAlgorithm().getParameters().toASN1Primitive().getEncoded(ASN1Encoding_Fields.DER);
				}
				catch (IOException)
				{
					return null;
				}
			}
			else
			{
				return null;
			}
		}

		public virtual bool[] getIssuerUniqueID()
		{
			DERBitString id = c.getTBSCertificate().getIssuerUniqueId();

			if (id != null)
			{
				byte[] bytes = id.getBytes();
				bool[] boolId = new bool[bytes.Length * 8 - id.getPadBits()];

				for (int i = 0; i != boolId.Length; i++)
				{
					boolId[i] = (bytes[i / 8] & ((int)((uint)0x80 >> (i % 8)))) != 0;
				}

				return boolId;
			}

			return null;
		}

		public virtual bool[] getSubjectUniqueID()
		{
			DERBitString id = c.getTBSCertificate().getSubjectUniqueId();

			if (id != null)
			{
				byte[] bytes = id.getBytes();
				bool[] boolId = new bool[bytes.Length * 8 - id.getPadBits()];

				for (int i = 0; i != boolId.Length; i++)
				{
					boolId[i] = (bytes[i / 8] & ((int)((uint)0x80 >> (i % 8)))) != 0;
				}

				return boolId;
			}

			return null;
		}

		public virtual bool[] getKeyUsage()
		{
			return keyUsage;
		}

		public virtual List getExtendedKeyUsage()
		{
			byte[] bytes = this.getExtensionBytes("2.5.29.37");

			if (bytes != null)
			{
				try
				{
					ASN1InputStream dIn = new ASN1InputStream(bytes);
					ASN1Sequence seq = (ASN1Sequence)dIn.readObject();
					List list = new ArrayList();

					for (int i = 0; i != seq.size(); i++)
					{
						list.add(((ASN1ObjectIdentifier)seq.getObjectAt(i)).getId());
					}

					return Collections.unmodifiableList(list);
				}
				catch (Exception)
				{
					throw new CertificateParsingException("error processing extended key usage extension");
				}
			}

			return null;
		}

		public virtual int getBasicConstraints()
		{
			if (basicConstraints != null)
			{
				if (basicConstraints.isCA())
				{
					if (basicConstraints.getPathLenConstraint() == null)
					{
						return int.MaxValue;
					}
					else
					{
						return basicConstraints.getPathLenConstraint().intValue();
					}
				}
				else
				{
					return -1;
				}
			}

			return -1;
		}

		public virtual Collection getSubjectAlternativeNames()
		{
			return getAlternativeNames(getExtensionBytes(Extension.subjectAlternativeName.getId()));
		}

		public virtual Collection getIssuerAlternativeNames()
		{
			return getAlternativeNames(getExtensionBytes(Extension.issuerAlternativeName.getId()));
		}

		public virtual Set getCriticalExtensionOIDs()
		{
			if (this.getVersion() == 3)
			{
				Set set = new HashSet();
				Extensions extensions = c.getTBSCertificate().getExtensions();

				if (extensions != null)
				{
					Enumeration e = extensions.oids();

					while (e.hasMoreElements())
					{
						ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
						Extension ext = extensions.getExtension(oid);

						if (ext.isCritical())
						{
							set.add(oid.getId());
						}
					}

					return set;
				}
			}

			return null;
		}

		private byte[] getExtensionBytes(string oid)
		{
			Extensions exts = c.getTBSCertificate().getExtensions();

			if (exts != null)
			{
				Extension ext = exts.getExtension(new ASN1ObjectIdentifier(oid));
				if (ext != null)
				{
					return ext.getExtnValue().getOctets();
				}
			}

			return null;
		}

		public virtual byte[] getExtensionValue(string oid)
		{
			Extensions exts = c.getTBSCertificate().getExtensions();

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

		public virtual Set getNonCriticalExtensionOIDs()
		{
			if (this.getVersion() == 3)
			{
				Set set = new HashSet();
				Extensions extensions = c.getTBSCertificate().getExtensions();

				if (extensions != null)
				{
					Enumeration e = extensions.oids();

					while (e.hasMoreElements())
					{
						ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
						Extension ext = extensions.getExtension(oid);

						if (!ext.isCritical())
						{
							set.add(oid.getId());
						}
					}

					return set;
				}
			}

			return null;
		}

		public virtual bool hasUnsupportedCriticalExtension()
		{
			if (this.getVersion() == 3)
			{
				Extensions extensions = c.getTBSCertificate().getExtensions();

				if (extensions != null)
				{
					Enumeration e = extensions.oids();

					while (e.hasMoreElements())
					{
						ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
						string oidId = oid.getId();

						if (oidId.Equals(RFC3280CertPathUtilities.KEY_USAGE) || oidId.Equals(RFC3280CertPathUtilities.CERTIFICATE_POLICIES) || oidId.Equals(RFC3280CertPathUtilities.POLICY_MAPPINGS) || oidId.Equals(RFC3280CertPathUtilities.INHIBIT_ANY_POLICY) || oidId.Equals(RFC3280CertPathUtilities.CRL_DISTRIBUTION_POINTS) || oidId.Equals(RFC3280CertPathUtilities.ISSUING_DISTRIBUTION_POINT) || oidId.Equals(RFC3280CertPathUtilities.DELTA_CRL_INDICATOR) || oidId.Equals(RFC3280CertPathUtilities.POLICY_CONSTRAINTS) || oidId.Equals(RFC3280CertPathUtilities.BASIC_CONSTRAINTS) || oidId.Equals(RFC3280CertPathUtilities.SUBJECT_ALTERNATIVE_NAME) || oidId.Equals(RFC3280CertPathUtilities.NAME_CONSTRAINTS))
						{
							continue;
						}

						Extension ext = extensions.getExtension(oid);

						if (ext.isCritical())
						{
							return true;
						}
					}
				}
			}

			return false;
		}

		public virtual PublicKey getPublicKey()
		{
			try
			{
				return BouncyCastleProvider.getPublicKey(c.getSubjectPublicKeyInfo());
			}
			catch (IOException)
			{
				return null; // should never happen...
			}
		}

		public virtual byte[] getEncoded()
		{
			try
			{
				return c.getEncoded(ASN1Encoding_Fields.DER);
			}
			catch (IOException e)
			{
				throw new CertificateEncodingException(e.ToString());
			}
		}

		public override bool Equals(object o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is Certificate))
			{
				return false;
			}

			Certificate other = (Certificate)o;

			try
			{
				byte[] b1 = this.getEncoded();
				byte[] b2 = other.getEncoded();

				return Arrays.areEqual(b1, b2);
			}
			catch (CertificateEncodingException)
			{
				return false;
			}
		}

		public override int GetHashCode()
		{
			lock (this)
			{
				if (!hashValueSet)
				{
					hashValue = calculateHashCode();
					hashValueSet = true;
				}
        
				return hashValue;
			}
		}

		private int calculateHashCode()
		{
			try
			{
				int hashCode = 0;
				byte[] certData = this.getEncoded();
				for (int i = 1; i < certData.Length; i++)
				{
					 hashCode += certData[i] * i;
				}
				return hashCode;
			}
			catch (CertificateEncodingException)
			{
				return 0;
			}
		}

		public virtual void setBagAttribute(ASN1ObjectIdentifier oid, ASN1Encodable attribute)
		{
			attrCarrier.setBagAttribute(oid, attribute);
		}

		public virtual ASN1Encodable getBagAttribute(ASN1ObjectIdentifier oid)
		{
			return attrCarrier.getBagAttribute(oid);
		}

		public virtual Enumeration getBagAttributeKeys()
		{
			return attrCarrier.getBagAttributeKeys();
		}

		public override string ToString()
		{
			StringBuffer buf = new StringBuffer();
			string nl = Strings.lineSeparator();

			buf.append("  [0]         Version: ").append(this.getVersion()).append(nl);
			buf.append("         SerialNumber: ").append(this.getSerialNumber()).append(nl);
			buf.append("             IssuerDN: ").append(this.getIssuerDN()).append(nl);
			buf.append("           Start Date: ").append(this.getNotBefore()).append(nl);
			buf.append("           Final Date: ").append(this.getNotAfter()).append(nl);
			buf.append("            SubjectDN: ").append(this.getSubjectDN()).append(nl);
			buf.append("           Public Key: ").append(this.getPublicKey()).append(nl);
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

			Extensions extensions = c.getTBSCertificate().getExtensions();

			if (extensions != null)
			{
				Enumeration e = extensions.oids();

				if (e.hasMoreElements())
				{
					buf.append("       Extensions: \n");
				}

				while (e.hasMoreElements())
				{
					ASN1ObjectIdentifier oid = (ASN1ObjectIdentifier)e.nextElement();
					Extension ext = extensions.getExtension(oid);

					if (ext.getExtnValue() != null)
					{
						byte[] octs = ext.getExtnValue().getOctets();
						ASN1InputStream dIn = new ASN1InputStream(octs);
						buf.append("                       critical(").append(ext.isCritical()).append(") ");
						try
						{
							if (oid.Equals(Extension.basicConstraints))
							{
								buf.append(BasicConstraints.getInstance(dIn.readObject())).append(nl);
							}
							else if (oid.Equals(Extension.keyUsage))
							{
								buf.append(KeyUsage.getInstance(dIn.readObject())).append(nl);
							}
							else if (oid.Equals(MiscObjectIdentifiers_Fields.netscapeCertType))
							{
								buf.append(new NetscapeCertType((DERBitString)dIn.readObject())).append(nl);
							}
							else if (oid.Equals(MiscObjectIdentifiers_Fields.netscapeRevocationURL))
							{
								buf.append(new NetscapeRevocationURL((DERIA5String)dIn.readObject())).append(nl);
							}
							else if (oid.Equals(MiscObjectIdentifiers_Fields.verisignCzagExtension))
							{
								buf.append(new VerisignCzagExtension((DERIA5String)dIn.readObject())).append(nl);
							}
							else
							{
								buf.append(oid.getId());
								buf.append(" value = ").append(ASN1Dump.dumpAsString(dIn.readObject())).append(nl);
								//buf.append(" value = ").append("*****").append(nl);
							}
						}
						catch (Exception)
						{
							buf.append(oid.getId());
					   //     buf.append(" value = ").append(new String(Hex.encode(ext.getExtnValue().getOctets()))).append(nl);
							buf.append(" value = ").append("*****").append(nl);
						}
					}
					else
					{
						buf.append(nl);
					}
				}
			}

			return buf.ToString();
		}

		public void verify(PublicKey key)
		{
			Signature signature;
			string sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());

			try
			{
				signature = Signature.getInstance(sigName, BouncyCastleProvider.PROVIDER_NAME);
			}
			catch (Exception)
			{
				signature = Signature.getInstance(sigName);
			}

			checkSignature(key, signature);
		}

		public void verify(PublicKey key, string sigProvider)
		{
			string sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
			Signature signature;

			if (!string.ReferenceEquals(sigProvider, null))
			{
				signature = Signature.getInstance(sigName, sigProvider);
			}
			else
			{
				signature = Signature.getInstance(sigName);
			}

			checkSignature(key, signature);
		}

		public void verify(PublicKey key, Provider sigProvider)
		{
			string sigName = X509SignatureUtil.getSignatureName(c.getSignatureAlgorithm());
			Signature signature;

			if (sigProvider != null)
			{
				signature = Signature.getInstance(sigName, sigProvider);
			}
			else
			{
				signature = Signature.getInstance(sigName);
			}

			checkSignature(key, signature);
		}

		private void checkSignature(PublicKey key, Signature signature)
		{
			if (!isAlgIdEqual(c.getSignatureAlgorithm(), c.getTBSCertificate().getSignature()))
			{
				throw new CertificateException("signature algorithm in TBS cert not same as outer cert");
			}

			ASN1Encodable @params = c.getSignatureAlgorithm().getParameters();

			// TODO This should go after the initVerify?
			X509SignatureUtil.setSignatureParameters(signature, @params);

			signature.initVerify(key);

			signature.update(this.getTBSCertificate());

			if (!signature.verify(this.getSignature()))
			{
				throw new SignatureException("certificate does not verify with supplied key");
			}
		}

		private bool isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2)
		{
			if (!id1.getAlgorithm().Equals(id2.getAlgorithm()))
			{
				return false;
			}

			if (id1.getParameters() == null)
			{
				if (id2.getParameters() != null && !id2.getParameters().Equals(DERNull.INSTANCE))
				{
					return false;
				}

				return true;
			}

			if (id2.getParameters() == null)
			{
				if (id1.getParameters() != null && !id1.getParameters().Equals(DERNull.INSTANCE))
				{
					return false;
				}

				return true;
			}

			return id1.getParameters().Equals(id2.getParameters());
		}

		private static Collection getAlternativeNames(byte[] extVal)
		{
			if (extVal == null)
			{
				return null;
			}
			try
			{
				Collection temp = new ArrayList();
				Enumeration it = ASN1Sequence.getInstance(extVal).getObjects();
				while (it.hasMoreElements())
				{
					GeneralName genName = GeneralName.getInstance(it.nextElement());
					List list = new ArrayList();
					list.add(Integers.valueOf(genName.getTagNo()));
					switch (genName.getTagNo())
					{
					case GeneralName.ediPartyName:
					case GeneralName.x400Address:
					case GeneralName.otherName:
						list.add(genName.getEncoded());
						break;
					case GeneralName.directoryName:
						list.add(X500Name.getInstance(RFC4519Style.INSTANCE, genName.getName()).ToString());
						break;
					case GeneralName.dNSName:
					case GeneralName.rfc822Name:
					case GeneralName.uniformResourceIdentifier:
						list.add(((ASN1String)genName.getName()).getString());
						break;
					case GeneralName.registeredID:
						list.add(ASN1ObjectIdentifier.getInstance(genName.getName()).getId());
						break;
					case GeneralName.iPAddress:
						byte[] addrBytes = DEROctetString.getInstance(genName.getName()).getOctets();
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final String addr;
						string addr;
						try
						{
							addr = InetAddress.getByAddress(addrBytes).getHostAddress();
						}
						catch (UnknownHostException)
						{
							continue;
						}
						list.add(addr);
						break;
					default:
						throw new IOException("Bad tag number: " + genName.getTagNo());
					}

					temp.add(Collections.unmodifiableList(list));
				}
				if (temp.size() == 0)
				{
					return null;
				}
				return Collections.unmodifiableCollection(temp);
			}
			catch (Exception e)
			{
				throw new CertificateParsingException(e.Message);
			}
		}
	}

}