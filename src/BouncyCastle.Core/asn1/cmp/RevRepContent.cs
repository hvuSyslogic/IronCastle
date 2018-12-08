using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.asn1.cmp
{

	using CertId = org.bouncycastle.asn1.crmf.CertId;
	using CertificateList = org.bouncycastle.asn1.x509.CertificateList;

	public class RevRepContent : ASN1Object
	{
		private ASN1Sequence status;
		private ASN1Sequence revCerts;
		private ASN1Sequence crls;

		private RevRepContent(ASN1Sequence seq)
		{
			Enumeration en = seq.getObjects();

			status = ASN1Sequence.getInstance(en.nextElement());
			while (en.hasMoreElements())
			{
				ASN1TaggedObject tObj = ASN1TaggedObject.getInstance(en.nextElement());

				if (tObj.getTagNo() == 0)
				{
					revCerts = ASN1Sequence.getInstance(tObj, true);
				}
				else
				{
					crls = ASN1Sequence.getInstance(tObj, true);
				}
			}
		}

		public static RevRepContent getInstance(object o)
		{
			if (o is RevRepContent)
			{
				return (RevRepContent)o;
			}

			if (o != null)
			{
				return new RevRepContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual PKIStatusInfo[] getStatus()
		{
			PKIStatusInfo[] results = new PKIStatusInfo[status.size()];

			for (int i = 0; i != results.Length; i++)
			{
				results[i] = PKIStatusInfo.getInstance(status.getObjectAt(i));
			}

			return results;
		}

		public virtual CertId[] getRevCerts()
		{
			if (revCerts == null)
			{
				return null;
			}

			CertId[] results = new CertId[revCerts.size()];

			for (int i = 0; i != results.Length; i++)
			{
				results[i] = CertId.getInstance(revCerts.getObjectAt(i));
			}

			return results;
		}

		public virtual CertificateList[] getCrls()
		{
			if (crls == null)
			{
				return null;
			}

			CertificateList[] results = new CertificateList[crls.size()];

			for (int i = 0; i != results.Length; i++)
			{
				results[i] = CertificateList.getInstance(crls.getObjectAt(i));
			}

			return results;
		}

		/// <summary>
		/// <pre>
		/// RevRepContent ::= SEQUENCE {
		///        status       SEQUENCE SIZE (1..MAX) OF PKIStatusInfo,
		///        -- in same order as was sent in RevReqContent
		///        revCerts [0] SEQUENCE SIZE (1..MAX) OF CertId OPTIONAL,
		///        -- IDs for which revocation was requested
		///        -- (same order as status)
		///        crls     [1] SEQUENCE SIZE (1..MAX) OF CertificateList OPTIONAL
		///        -- the resulting CRLs (there may be more than one)
		///   }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(status);

			addOptional(v, 0, revCerts);
			addOptional(v, 1, crls);

			return new DERSequence(v);
		}

		private void addOptional(ASN1EncodableVector v, int tagNo, ASN1Encodable obj)
		{
			if (obj != null)
			{
				v.add(new DERTaggedObject(true, tagNo, obj));
			}
		}
	}

}