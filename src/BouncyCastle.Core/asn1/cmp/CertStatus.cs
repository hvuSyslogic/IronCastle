using BouncyCastle.Core.Port;

namespace org.bouncycastle.asn1.cmp
{


	public class CertStatus : ASN1Object
	{
		private ASN1OctetString certHash;
		private ASN1Integer certReqId;
		private PKIStatusInfo statusInfo;

		private CertStatus(ASN1Sequence seq)
		{
			certHash = ASN1OctetString.getInstance(seq.getObjectAt(0));
			certReqId = ASN1Integer.getInstance(seq.getObjectAt(1));

			if (seq.size() > 2)
			{
				statusInfo = PKIStatusInfo.getInstance(seq.getObjectAt(2));
			}
		}

		public CertStatus(byte[] certHash, BigInteger certReqId)
		{
			this.certHash = new DEROctetString(certHash);
			this.certReqId = new ASN1Integer(certReqId);
		}

		public CertStatus(byte[] certHash, BigInteger certReqId, PKIStatusInfo statusInfo)
		{
			this.certHash = new DEROctetString(certHash);
			this.certReqId = new ASN1Integer(certReqId);
			this.statusInfo = statusInfo;
		}

		public static CertStatus getInstance(object o)
		{
			if (o is CertStatus)
			{
				return (CertStatus)o;
			}

			if (o != null)
			{
				return new CertStatus(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual ASN1OctetString getCertHash()
		{
			return certHash;
		}

		public virtual ASN1Integer getCertReqId()
		{
			return certReqId;
		}

		public virtual PKIStatusInfo getStatusInfo()
		{
			return statusInfo;
		}

		/// <summary>
		/// <pre>
		/// CertStatus ::= SEQUENCE {
		///                   certHash    OCTET STRING,
		///                   -- the hash of the certificate, using the same hash algorithm
		///                   -- as is used to create and verify the certificate signature
		///                   certReqId   INTEGER,
		///                   -- to match this confirmation with the corresponding req/rep
		///                   statusInfo  PKIStatusInfo OPTIONAL
		/// }
		/// </pre> </summary>
		/// <returns> a basic ASN.1 object representation. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certHash);
			v.add(certReqId);

			if (statusInfo != null)
			{
				v.add(statusInfo);
			}

			return new DERSequence(v);
		}
	}

}