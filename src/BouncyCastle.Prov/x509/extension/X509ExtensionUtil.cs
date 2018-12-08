using System;

namespace org.bouncycastle.x509.extension
{

	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1OctetString = org.bouncycastle.asn1.ASN1OctetString;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using ASN1String = org.bouncycastle.asn1.ASN1String;
	using DEROctetString = org.bouncycastle.asn1.DEROctetString;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using X500Name = org.bouncycastle.asn1.x500.X500Name;
	using Extension = org.bouncycastle.asn1.x509.Extension;
	using GeneralName = org.bouncycastle.asn1.x509.GeneralName;
	using Integers = org.bouncycastle.util.Integers;


	/// @deprecated use org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils 
	public class X509ExtensionUtil
	{
		/// @deprecated use org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.parseExtensionValue() 
		public static ASN1Primitive fromExtensionValue(byte[] encodedValue)
		{
			ASN1OctetString octs = (ASN1OctetString)ASN1Primitive.fromByteArray(encodedValue);

			return ASN1Primitive.fromByteArray(octs.getOctets());
		}

		/// @deprecated use org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.getIssuerAlternativeNames() 
		public static Collection getIssuerAlternativeNames(X509Certificate cert)
		{
			byte[] extVal = cert.getExtensionValue(Extension.issuerAlternativeName.getId());

			return getAlternativeNames(extVal);
		}

		/// @deprecated use org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils.getSubjectAlternativeNames() 
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
				Enumeration it = DERSequence.getInstance(fromExtensionValue(extVal)).getObjects();
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
	}

}