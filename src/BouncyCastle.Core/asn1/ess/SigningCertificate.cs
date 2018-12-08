using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.ess
{
	using PolicyInformation = org.bouncycastle.asn1.x509.PolicyInformation;


	public class SigningCertificate : ASN1Object
	{
		internal ASN1Sequence certs;
		internal ASN1Sequence policies;

		public static SigningCertificate getInstance(object o)
		{
			if (o is SigningCertificate)
			{
				return (SigningCertificate) o;
			}
			else if (o != null)
			{
				return new SigningCertificate(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		/// <summary>
		/// constructeurs
		/// </summary>
		private SigningCertificate(ASN1Sequence seq)
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

		public SigningCertificate(ESSCertID essCertID)
		{
			certs = new DERSequence(essCertID);
		}

		public virtual ESSCertID[] getCerts()
		{
			ESSCertID[] cs = new ESSCertID[certs.size()];

			for (int i = 0; i != certs.size(); i++)
			{
				cs[i] = ESSCertID.getInstance(certs.getObjectAt(i));
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
		/// The definition of SigningCertificate is
		/// <pre>
		/// SigningCertificate ::=  SEQUENCE {
		///      certs        SEQUENCE OF ESSCertID,
		///      policies     SEQUENCE OF PolicyInformation OPTIONAL
		/// }
		/// </pre>
		/// id-aa-signingCertificate OBJECT IDENTIFIER ::= { iso(1)
		///  member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs9(9)
		///  smime(16) id-aa(2) 12 }
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