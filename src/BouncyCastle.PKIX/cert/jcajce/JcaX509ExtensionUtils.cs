using org.bouncycastle.asn1.oiw;

using System;

namespace org.bouncycastle.cert.jcajce
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1String = org.bouncycastle.asn1.ASN1String;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using OIWObjectIdentifiers = org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AuthorityKeyIdentifier = org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using GeneralNames = org.bouncycastle.asn1.x509.GeneralNames;
	using SubjectKeyIdentifier = org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
	using SubjectPublicKeyInfo = org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
	using DigestCalculator = org.bouncycastle.@operator.DigestCalculator;
	using Integers = org.bouncycastle.util.Integers;

	public class JcaX509ExtensionUtils : X509ExtensionUtils
	{
		/// <summary>
		/// Create a utility class pre-configured with a SHA-1 digest calculator based on the
		/// default implementation.
		/// </summary>
		/// <exception cref="NoSuchAlgorithmException"> </exception>
		public JcaX509ExtensionUtils() : base(new SHA1DigestCalculator(MessageDigest.getInstance("SHA1")))
		{
		}

		public JcaX509ExtensionUtils(DigestCalculator calculator) : base(calculator)
		{
		}

		public virtual AuthorityKeyIdentifier createAuthorityKeyIdentifier(X509Certificate cert)
		{
			return base.createAuthorityKeyIdentifier(new JcaX509CertificateHolder(cert));
		}

		public virtual AuthorityKeyIdentifier createAuthorityKeyIdentifier(PublicKey pubKey)
		{
			return base.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
		}

		public virtual AuthorityKeyIdentifier createAuthorityKeyIdentifier(PublicKey pubKey, X500Principal name, BigInteger serial)
		{
			return base.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()), new GeneralNames(new GeneralName(X500Name.getInstance(name.getEncoded()))), serial);
		}

		public virtual AuthorityKeyIdentifier createAuthorityKeyIdentifier(PublicKey pubKey, GeneralNames generalNames, BigInteger serial)
		{
			return base.createAuthorityKeyIdentifier(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()), generalNames, serial);
		}

		/// <summary>
		/// Return a RFC 3280 type 1 key identifier. As in:
		/// <pre>
		/// (1) The keyIdentifier is composed of the 160-bit SHA-1 hash of the
		/// value of the BIT STRING subjectPublicKey (excluding the tag,
		/// length, and number of unused bits).
		/// </pre> </summary>
		/// <param name="publicKey"> the key object containing the key identifier is to be based on. </param>
		/// <returns> the key identifier. </returns>
		public virtual SubjectKeyIdentifier createSubjectKeyIdentifier(PublicKey publicKey)
		{
			return base.createSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
		}

		/// <summary>
		/// Return a RFC 3280 type 2 key identifier. As in:
		/// <pre>
		/// (2) The keyIdentifier is composed of a four bit type field with
		/// the value 0100 followed by the least significant 60 bits of the
		/// SHA-1 hash of the value of the BIT STRING subjectPublicKey.
		/// </pre> </summary>
		/// <param name="publicKey"> the key object of interest. </param>
		/// <returns> the key identifier. </returns>
		public virtual SubjectKeyIdentifier createTruncatedSubjectKeyIdentifier(PublicKey publicKey)
		{
		   return base.createTruncatedSubjectKeyIdentifier(SubjectPublicKeyInfo.getInstance(publicKey.getEncoded()));
		}

		/// <summary>
		/// Return the ASN.1 object contained in a byte[] returned by a getExtensionValue() call.
		/// </summary>
		/// <param name="encExtValue"> DER encoded OCTET STRING containing the DER encoded extension object. </param>
		/// <returns> an ASN.1 object </returns>
		/// <exception cref="java.io.IOException"> on a parsing error. </exception>
		public static ASN1Primitive parseExtensionValue(byte[] encExtValue)
		{
			return ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(encExtValue).getOctets());
		}

		public static Collection getIssuerAlternativeNames(X509Certificate cert)
		{
			byte[] extVal = cert.getExtensionValue(Extension.issuerAlternativeName.getId());

			return getAlternativeNames(extVal);
		}

		public static Collection getSubjectAlternativeNames(X509Certificate cert)
		{
			byte[] extVal = cert.getExtensionValue(Extension.subjectAlternativeName.getId());

			return getAlternativeNames(extVal);
		}

		private static Collection getAlternativeNames(byte[] extVal)
		{
			if (extVal == null)
			{
				return Collections.EMPTY_LIST;
			}
			try
			{
				Collection temp = new ArrayList();
				Enumeration it = DERSequence.getInstance(parseExtensionValue(extVal)).getObjects();
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
						list.add(genName.getName().toASN1Primitive());
						break;
					case GeneralName.directoryName:
						list.add(X500Name.getInstance(genName.getName()).ToString());
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
						list.add(DEROctetString.getInstance(genName.getName()).getOctets());
						break;
					default:
						throw new IOException("Bad tag number: " + genName.getTagNo());
					}

					temp.add(list);
				}
				return Collections.unmodifiableCollection(temp);
			}
			catch (Exception e)
			{
				throw new CertificateParsingException(e.Message);
			}
		}

		public class SHA1DigestCalculator : DigestCalculator
		{
			internal ByteArrayOutputStream bOut = new ByteArrayOutputStream();
			internal MessageDigest digest;

			public SHA1DigestCalculator(MessageDigest digest)
			{
				this.digest = digest;
			}

			public virtual AlgorithmIdentifier getAlgorithmIdentifier()
			{
				return new AlgorithmIdentifier(OIWObjectIdentifiers_Fields.idSHA1);
			}

			public virtual OutputStream getOutputStream()
			{
				return bOut;
			}

			public virtual byte[] getDigest()
			{
				byte[] bytes = digest.digest(bOut.toByteArray());

				bOut.reset();

				return bytes;
			}
		}
	}

}