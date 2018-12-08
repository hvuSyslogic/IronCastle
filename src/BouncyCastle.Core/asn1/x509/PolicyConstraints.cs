using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x509
{


	/// <summary>
	/// PKIX RFC 5280
	/// <pre>
	/// id-ce-policyConstraints OBJECT IDENTIFIER ::=  { id-ce 36 }
	/// 
	/// PolicyConstraints ::= SEQUENCE {
	///      requireExplicitPolicy           [0] SkipCerts OPTIONAL,
	///      inhibitPolicyMapping            [1] SkipCerts OPTIONAL }
	/// 
	/// SkipCerts ::= INTEGER (0..MAX)
	/// </pre>
	/// </summary>
	public class PolicyConstraints : ASN1Object
	{
		private BigInteger requireExplicitPolicyMapping;
		private BigInteger inhibitPolicyMapping;

		public PolicyConstraints(BigInteger requireExplicitPolicyMapping, BigInteger inhibitPolicyMapping)
		{
			this.requireExplicitPolicyMapping = requireExplicitPolicyMapping;
			this.inhibitPolicyMapping = inhibitPolicyMapping;
		}

		private PolicyConstraints(ASN1Sequence seq)
		{
			for (int i = 0; i != seq.size(); i++)
			{
				ASN1TaggedObject to = ASN1TaggedObject.getInstance(seq.getObjectAt(i));

				if (to.getTagNo() == 0)
				{
					requireExplicitPolicyMapping = ASN1Integer.getInstance(to, false).getValue();
				}
				else if (to.getTagNo() == 1)
				{
					inhibitPolicyMapping = ASN1Integer.getInstance(to, false).getValue();
				}
				else
				{
					throw new IllegalArgumentException("Unknown tag encountered.");
				}
			}
		}

		public static PolicyConstraints getInstance(object obj)
		{
			if (obj is PolicyConstraints)
			{
				return (PolicyConstraints)obj;
			}

			if (obj != null)
			{
				return new PolicyConstraints(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public static PolicyConstraints fromExtensions(Extensions extensions)
		{
			return PolicyConstraints.getInstance(extensions.getExtensionParsedValue(Extension.policyConstraints));
		}

		public virtual BigInteger getRequireExplicitPolicyMapping()
		{
			return requireExplicitPolicyMapping;
		}

		public virtual BigInteger getInhibitPolicyMapping()
		{
			return inhibitPolicyMapping;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			if (requireExplicitPolicyMapping != null)
			{
				v.add(new DERTaggedObject(false,0, new ASN1Integer(requireExplicitPolicyMapping)));
			}

			if (inhibitPolicyMapping != null)
			{
				v.add(new DERTaggedObject(false, 1, new ASN1Integer(inhibitPolicyMapping)));
			}

			return new DERSequence(v);
		}
	}

}