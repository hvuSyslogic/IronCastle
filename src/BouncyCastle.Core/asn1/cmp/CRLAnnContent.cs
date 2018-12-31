using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.asn1.cmp
{
	
	public class CRLAnnContent : ASN1Object
	{
		private ASN1Sequence content;

		private CRLAnnContent(ASN1Sequence seq)
		{
			content = seq;
		}

		public static CRLAnnContent getInstance(object o)
		{
			if (o is CRLAnnContent)
			{
				return (CRLAnnContent)o;
			}

			if (o != null)
			{
				return new CRLAnnContent(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public CRLAnnContent(CertificateList crl)
		{
			this.content = new DERSequence(crl);
		}

		public virtual CertificateList[] getCertificateLists()
		{
			CertificateList[] result = new CertificateList[content.size()];

			for (int i = 0; i != result.Length; i++)
			{
				result[i] = CertificateList.getInstance(content.getObjectAt(i));
			}

			return result;
		}

		/// <summary>
		/// <pre>
		/// CRLAnnContent ::= SEQUENCE OF CertificateList
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return content;
		}
	}

}