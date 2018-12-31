using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.ess
{
	
	public class OtherSigningCertificate : ASN1Object
	{
		internal ASN1Sequence certs;
		internal ASN1Sequence policies;

		public static OtherSigningCertificate getInstance(object o)
		{
			if (o is OtherSigningCertificate)
			{
				return (OtherSigningCertificate) o;
			}
			else if (o != null)
			{
				return new OtherSigningCertificate(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// constructeurs
		/// </summary>
		private OtherSigningCertificate(ASN1Sequence seq)
		{
			if (seq.size() < 1 || seq.size() > 2)
			{
				throw new IllegalArgumentException("Bad sequence size: " + seq.size());
			}

			this.certs = ASN1Sequence.getInstance(seq.getObjectAt(0));

			if (seq.size() > 1)
			{
				this.policies = ASN1Sequence.getInstance(seq.getObjectAt(1));
			}
		}

		public OtherSigningCertificate(OtherCertID otherCertID)
		{
			certs = new DERSequence(otherCertID);
		}

		public virtual OtherCertID[] getCerts()
		{
			OtherCertID[] cs = new OtherCertID[certs.size()];

			for (int i = 0; i != certs.size(); i++)
			{
				cs[i] = OtherCertID.getInstance(certs.getObjectAt(i));
			}

			return cs;
		}

		public virtual PolicyInformation[] getPolicies()
		{
			if (policies == null)
			{
				return null;
			}

			PolicyInformation[] ps = new PolicyInformation[policies.size()];

			for (int i = 0; i != policies.size(); i++)
			{
				ps[i] = PolicyInformation.getInstance(policies.getObjectAt(i));
			}

			return ps;
		}

		/// <summary>
		/// The definition of OtherSigningCertificate is
		/// <pre>
		/// OtherSigningCertificate ::=  SEQUENCE {
		///      certs        SEQUENCE OF OtherCertID,
		///      policies     SEQUENCE OF PolicyInformation OPTIONAL
		/// }
		/// </pre>
		/// id-aa-ets-otherSigCert OBJECT IDENTIFIER ::= { iso(1)
		///  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
		///  smime(16) id-aa(2) 19 }
		/// </summary>
		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(certs);

			if (policies != null)
			{
				v.add(policies);
			}

			return new DERSequence(v);
		}
	}

}