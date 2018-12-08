using System;

namespace org.bouncycastle.cert
{

	using ASN1Encodable = org.bouncycastle.asn1.ASN1Encodable;
	using ASN1EncodableVector = org.bouncycastle.asn1.ASN1EncodableVector;
	using ASN1GeneralizedTime = org.bouncycastle.asn1.ASN1GeneralizedTime;
	using ASN1ObjectIdentifier = org.bouncycastle.asn1.ASN1ObjectIdentifier;
	using ASN1Primitive = org.bouncycastle.asn1.ASN1Primitive;
	using DERBitString = org.bouncycastle.asn1.DERBitString;
	using DERNull = org.bouncycastle.asn1.DERNull;
	using DEROutputStream = org.bouncycastle.asn1.DEROutputStream;
	using DERSequence = org.bouncycastle.asn1.DERSequence;
	using AlgorithmIdentifier = org.bouncycastle.asn1.x509.AlgorithmIdentifier;
	using AttributeCertificate = org.bouncycastle.asn1.x509.AttributeCertificate;
	using AttributeCertificateInfo = org.bouncycastle.asn1.x509.AttributeCertificateInfo;
	using Certificate = org.bouncycastle.asn1.x509.Certificate;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;
	using Extensions = org.bouncycastle.asn1.x509.Extensions;
	using ExtensionsGenerator = org.bouncycastle.asn1.x509.ExtensionsGenerator;
	using TBSCertList = org.bouncycastle.asn1.x509.TBSCertList;
	using TBSCertificate = org.bouncycastle.asn1.x509.TBSCertificate;
	using ContentSigner = org.bouncycastle.@operator.ContentSigner;

	public class CertUtils
	{
		private static Set EMPTY_SET = Collections.unmodifiableSet(new HashSet());
		private static List EMPTY_LIST = Collections.unmodifiableList(new ArrayList());

		internal static ASN1Primitive parseNonEmptyASN1(byte[] encoding)
		{
			ASN1Primitive p = ASN1Primitive.fromByteArray(encoding);

			if (p == null)
			{
				throw new IOException("no content found");
			}
			return p;
		}

		internal static X509CertificateHolder generateFullCert(ContentSigner signer, TBSCertificate tbsCert)
		{
			try
			{
				return new X509CertificateHolder(generateStructure(tbsCert, signer.getAlgorithmIdentifier(), generateSig(signer, tbsCert)));
			}
			catch (IOException)
			{
				throw new IllegalStateException("cannot produce certificate signature");
			}
		}

		internal static X509AttributeCertificateHolder generateFullAttrCert(ContentSigner signer, AttributeCertificateInfo attrInfo)
		{
			try
			{
				return new X509AttributeCertificateHolder(generateAttrStructure(attrInfo, signer.getAlgorithmIdentifier(), generateSig(signer, attrInfo)));
			}
			catch (IOException)
			{
				throw new IllegalStateException("cannot produce attribute certificate signature");
			}
		}

		internal static X509CRLHolder generateFullCRL(ContentSigner signer, TBSCertList tbsCertList)
		{
			try
			{
				return new X509CRLHolder(generateCRLStructure(tbsCertList, signer.getAlgorithmIdentifier(), generateSig(signer, tbsCertList)));
			}
			catch (IOException)
			{
				throw new IllegalStateException("cannot produce certificate signature");
			}
		}

		private static byte[] generateSig(ContentSigner signer, ASN1Encodable tbsObj)
		{
			OutputStream sOut = signer.getOutputStream();
			DEROutputStream dOut = new DEROutputStream(sOut);

			dOut.writeObject(tbsObj);

			sOut.close();

			return signer.getSignature();
		}

		private static Certificate generateStructure(TBSCertificate tbsCert, AlgorithmIdentifier sigAlgId, byte[] signature)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsCert);
			v.add(sigAlgId);
			v.add(new DERBitString(signature));

			return Certificate.getInstance(new DERSequence(v));
		}

		private static AttributeCertificate generateAttrStructure(AttributeCertificateInfo attrInfo, AlgorithmIdentifier sigAlgId, byte[] signature)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(attrInfo);
			v.add(sigAlgId);
			v.add(new DERBitString(signature));

			return AttributeCertificate.getInstance(new DERSequence(v));
		}

		private static CertificateList generateCRLStructure(TBSCertList tbsCertList, AlgorithmIdentifier sigAlgId, byte[] signature)
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(tbsCertList);
			v.add(sigAlgId);
			v.add(new DERBitString(signature));

			return CertificateList.getInstance(new DERSequence(v));
		}

		internal static Set getCriticalExtensionOIDs(Extensions extensions)
		{
			if (extensions == null)
			{
				return EMPTY_SET;
			}

			return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getCriticalExtensionOIDs())));
		}

		internal static Set getNonCriticalExtensionOIDs(Extensions extensions)
		{
			if (extensions == null)
			{
				return EMPTY_SET;
			}

			// TODO: should probably produce a set that imposes correct ordering
			return Collections.unmodifiableSet(new HashSet(Arrays.asList(extensions.getNonCriticalExtensionOIDs())));
		}

		internal static List getExtensionOIDs(Extensions extensions)
		{
			if (extensions == null)
			{
				return EMPTY_LIST;
			}

			return Collections.unmodifiableList(Arrays.asList(extensions.getExtensionOIDs()));
		}

		internal static void addExtension(ExtensionsGenerator extGenerator, ASN1ObjectIdentifier oid, bool isCritical, ASN1Encodable value)
		{
			try
			{
				extGenerator.addExtension(oid, isCritical, value);
			}
			catch (IOException e)
			{
				throw new CertIOException("cannot encode extension: " + e.Message, e);
			}
		}

		internal static DERBitString booleanToBitString(bool[] id)
		{
			byte[] bytes = new byte[(id.Length + 7) / 8];

			for (int i = 0; i != id.Length; i++)
			{
				bytes[i / 8] |= (byte)((id[i]) ? (1 << ((7 - (i % 8)))) : 0);
			}

			int pad = id.Length % 8;

			if (pad == 0)
			{
				return new DERBitString(bytes);
			}
			else
			{
				return new DERBitString(bytes, 8 - pad);
			}
		}

		internal static bool[] bitStringToBoolean(DERBitString bitString)
		{
			if (bitString != null)
			{
				byte[] bytes = bitString.getBytes();
				bool[] boolId = new bool[bytes.Length * 8 - bitString.getPadBits()];

				for (int i = 0; i != boolId.Length; i++)
				{
					boolId[i] = (bytes[i / 8] & ((int)((uint)0x80 >> (i % 8)))) != 0;
				}

				return boolId;
			}

			return null;
		}

		internal static DateTime recoverDate(ASN1GeneralizedTime time)
		{
			try
			{
				return time.getDate();
			}
			catch (ParseException e)
			{
				throw new IllegalStateException("unable to recover date: " + e.Message);
			}
		}

		internal static bool isAlgIdEqual(AlgorithmIdentifier id1, AlgorithmIdentifier id2)
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
	}

}