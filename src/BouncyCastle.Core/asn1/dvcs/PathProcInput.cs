using org.bouncycastle.asn1.x509;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.dvcs
{

	
	/// <summary>
	/// <pre>
	///     PathProcInput ::= SEQUENCE {
	///         acceptablePolicySet          SEQUENCE SIZE (1..MAX) OF
	///                                         PolicyInformation,
	///         inhibitPolicyMapping         BOOLEAN DEFAULT FALSE,
	///         explicitPolicyReqd           [0] BOOLEAN DEFAULT FALSE ,
	///         inhibitAnyPolicy             [1] BOOLEAN DEFAULT FALSE
	///     }
	/// </pre>
	/// </summary>
	public class PathProcInput : ASN1Object
	{
		private PolicyInformation[] acceptablePolicySet;
		private bool inhibitPolicyMapping = false;
		private bool explicitPolicyReqd = false;
		private bool inhibitAnyPolicy = false;

		public PathProcInput(PolicyInformation[] acceptablePolicySet)
		{
			this.acceptablePolicySet = copy(acceptablePolicySet);
		}

		public PathProcInput(PolicyInformation[] acceptablePolicySet, bool inhibitPolicyMapping, bool explicitPolicyReqd, bool inhibitAnyPolicy)
		{
			this.acceptablePolicySet = copy(acceptablePolicySet);
			this.inhibitPolicyMapping = inhibitPolicyMapping;
			this.explicitPolicyReqd = explicitPolicyReqd;
			this.inhibitAnyPolicy = inhibitAnyPolicy;
		}

		private static PolicyInformation[] fromSequence(ASN1Sequence seq)
		{
			PolicyInformation[] tmp = new PolicyInformation[seq.size()];

			for (int i = 0; i != tmp.Length; i++)
			{
				tmp[i] = PolicyInformation.getInstance(seq.getObjectAt(i));
			}

			return tmp;
		}

		public static PathProcInput getInstance(object obj)
		{
			if (obj is PathProcInput)
			{
				return (PathProcInput)obj;
			}
			else if (obj != null)
			{
				ASN1Sequence seq = ASN1Sequence.getInstance(obj);
				ASN1Sequence policies = ASN1Sequence.getInstance(seq.getObjectAt(0));
				PathProcInput result = new PathProcInput(fromSequence(policies));

				for (int i = 1; i < seq.size(); i++)
				{
					object o = seq.getObjectAt(i);

					if (o is ASN1Boolean)
					{
						ASN1Boolean x = ASN1Boolean.getInstance(o);
						result.setInhibitPolicyMapping(x.isTrue());
					}
					else if (o is ASN1TaggedObject)
					{
						ASN1TaggedObject t = ASN1TaggedObject.getInstance(o);
						ASN1Boolean x;
						switch (t.getTagNo())
						{
						case 0:
							x = ASN1Boolean.getInstance(t, false);
							result.setExplicitPolicyReqd(x.isTrue());
							break;
						case 1:
							x = ASN1Boolean.getInstance(t, false);
							result.setInhibitAnyPolicy(x.isTrue());
							break;
						default:
							throw new IllegalArgumentException("Unknown tag encountered: " + t.getTagNo());
						}
					}
				}
				return result;
			}

			return null;
		}

		public static PathProcInput getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Sequence.getInstance(obj, @explicit));
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();
			ASN1EncodableVector pV = new ASN1EncodableVector();

			for (int i = 0; i != acceptablePolicySet.Length; i++)
			{
				pV.add(acceptablePolicySet[i]);
			}

			v.add(new DERSequence(pV));

			if (inhibitPolicyMapping)
			{
				v.add(ASN1Boolean.getInstance(inhibitPolicyMapping));
			}
			if (explicitPolicyReqd)
			{
				v.add(new DERTaggedObject(false, 0, ASN1Boolean.getInstance(explicitPolicyReqd)));
			}
			if (inhibitAnyPolicy)
			{
				v.add(new DERTaggedObject(false, 1, ASN1Boolean.getInstance(inhibitAnyPolicy)));
			}

			return new DERSequence(v);
		}

		public override string ToString()
		{
			return "PathProcInput: {\n" +
				"acceptablePolicySet: " + Arrays.asList(acceptablePolicySet) + "\n" +
				"inhibitPolicyMapping: " + inhibitPolicyMapping + "\n" +
				"explicitPolicyReqd: " + explicitPolicyReqd + "\n" +
				"inhibitAnyPolicy: " + inhibitAnyPolicy + "\n" +
				"}\n";
		}

		public virtual PolicyInformation[] getAcceptablePolicySet()
		{
			return copy(acceptablePolicySet);
		}

		public virtual bool isInhibitPolicyMapping()
		{
			return inhibitPolicyMapping;
		}

		private void setInhibitPolicyMapping(bool inhibitPolicyMapping)
		{
			this.inhibitPolicyMapping = inhibitPolicyMapping;
		}

		public virtual bool isExplicitPolicyReqd()
		{
			return explicitPolicyReqd;
		}

		private void setExplicitPolicyReqd(bool explicitPolicyReqd)
		{
			this.explicitPolicyReqd = explicitPolicyReqd;
		}

		public virtual bool isInhibitAnyPolicy()
		{
			return inhibitAnyPolicy;
		}

		private void setInhibitAnyPolicy(bool inhibitAnyPolicy)
		{
			this.inhibitAnyPolicy = inhibitAnyPolicy;
		}

		private PolicyInformation[] copy(PolicyInformation[] policySet)
		{
			PolicyInformation[] rv = new PolicyInformation[policySet.Length];

			JavaSystem.arraycopy(policySet, 0, rv, 0, rv.Length);

			return rv;
		}
	}

}