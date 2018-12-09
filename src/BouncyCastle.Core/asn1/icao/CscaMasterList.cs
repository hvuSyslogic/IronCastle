﻿using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.icao
{
	using Certificate = org.bouncycastle.asn1.x509.Certificate;

	/// <summary>
	/// The CscaMasterList object. This object can be wrapped in a
	/// CMSSignedData to be published in LDAP.
	/// 
	/// <pre>
	/// CscaMasterList ::= SEQUENCE {
	///   version                CscaMasterListVersion,
	///   certList               SET OF Certificate }
	/// 
	/// CscaMasterListVersion :: INTEGER {v0(0)}
	/// </pre>
	/// </summary>

	public class CscaMasterList : ASN1Object
	{
		private ASN1Integer version = new ASN1Integer(0);
		private Certificate[] certList;

		public static CscaMasterList getInstance(object obj)
		{
			if (obj is CscaMasterList)
			{
				return (CscaMasterList)obj;
			}
			else if (obj != null)
			{
				return new CscaMasterList(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		private CscaMasterList(ASN1Sequence seq)
		{
			if (seq == null || seq.size() == 0)
			{
				throw new IllegalArgumentException("null or empty sequence passed.");
			}
			if (seq.size() != 2)
			{
				throw new IllegalArgumentException("Incorrect sequence size: " + seq.size());
			}

			version = ASN1Integer.getInstance(seq.getObjectAt(0));
			ASN1Set certSet = ASN1Set.getInstance(seq.getObjectAt(1));
			certList = new Certificate[certSet.size()];
			for (int i = 0; i < certList.Length; i++)
			{
				certList[i] = Certificate.getInstance(certSet.getObjectAt(i));
			}
		}

		public CscaMasterList(Certificate[] certStructs)
		{
			certList = copyCertList(certStructs);
		}

		public virtual int getVersion()
		{
			return version.getValue().intValue();
		}

		public virtual Certificate[] getCertStructs()
		{
			return copyCertList(certList);
		}

		private Certificate[] copyCertList(Certificate[] orig)
		{
			Certificate[] certs = new Certificate[orig.Length];

			for (int i = 0; i != certs.Length; i++)
			{
				certs[i] = orig[i];
			}

			return certs;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector seq = new ASN1EncodableVector();

			seq.add(version);

			ASN1EncodableVector certSet = new ASN1EncodableVector();
			for (int i = 0; i < certList.Length; i++)
			{
				certSet.add(certList[i]);
			}
			seq.add(new DERSet(certSet));

			return new DERSequence(seq);
		}
	}

}