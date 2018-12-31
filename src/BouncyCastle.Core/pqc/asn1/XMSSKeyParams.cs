using org.bouncycastle.asn1;
using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.pqc.asn1
{
							
	/// <summary>
	/// XMSSKeyParams
	/// <pre>
	///     XMSSKeyParams ::= SEQUENCE {
	///     version INTEGER -- 0
	///     height INTEGER
	///     treeDigest AlgorithmIdentifier
	/// }
	/// </pre>
	/// </summary>
	public class XMSSKeyParams : ASN1Object
	{
		private readonly ASN1Integer version;
		private readonly int height;
		private readonly AlgorithmIdentifier treeDigest;

		public XMSSKeyParams(int height, AlgorithmIdentifier treeDigest)
		{
			this.version = new ASN1Integer(0);
			this.height = height;
			this.treeDigest = treeDigest;
		}

		private XMSSKeyParams(ASN1Sequence sequence)
		{
			this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
			this.height = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue().intValue();
			this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(2));
		}

		public static XMSSKeyParams getInstance(object o)
		{
			if (o is XMSSKeyParams)
			{
				return (XMSSKeyParams)o;
			}
			else if (o != null)
			{
				return new XMSSKeyParams(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual int getHeight()
		{
			return height;
		}

		public virtual AlgorithmIdentifier getTreeDigest()
		{
			return treeDigest;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			ASN1EncodableVector v = new ASN1EncodableVector();

			v.add(version);
			v.add(new ASN1Integer(height));
			v.add(treeDigest);

			return new DERSequence(v);
		}
	}

}