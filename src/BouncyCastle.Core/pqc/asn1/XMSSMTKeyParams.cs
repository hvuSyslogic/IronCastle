using org.bouncycastle.asn1;
using org.bouncycastle.asn1.x509;

namespace org.bouncycastle.pqc.asn1
{
							
	/// <summary>
	/// XMMSMTKeyParams
	/// <pre>
	///     XMMSMTKeyParams ::= SEQUENCE {
	///         version INTEGER -- 0
	///         height INTEGER
	///         layers INTEGER
	///         treeDigest AlgorithmIdentifier
	/// }
	/// </pre>
	/// </summary>
	public class XMSSMTKeyParams : ASN1Object
	{
		private readonly ASN1Integer version;
		private readonly int height;
		private readonly int layers;
		private readonly AlgorithmIdentifier treeDigest;

		public XMSSMTKeyParams(int height, int layers, AlgorithmIdentifier treeDigest)
		{
			this.version = new ASN1Integer(0);
			this.height = height;
			this.layers = layers;
			this.treeDigest = treeDigest;
		}

		private XMSSMTKeyParams(ASN1Sequence sequence)
		{
			this.version = ASN1Integer.getInstance(sequence.getObjectAt(0));
			this.height = ASN1Integer.getInstance(sequence.getObjectAt(1)).getValue().intValue();
			this.layers = ASN1Integer.getInstance(sequence.getObjectAt(2)).getValue().intValue();
			this.treeDigest = AlgorithmIdentifier.getInstance(sequence.getObjectAt(3));
		}

		public static XMSSMTKeyParams getInstance(object o)
		{
			if (o is XMSSMTKeyParams)
			{
				return (XMSSMTKeyParams)o;
			}
			else if (o != null)
			{
				return new XMSSMTKeyParams(ASN1Sequence.getInstance(o));
			}

			return null;
		}

		public virtual int getHeight()
		{
			return height;
		}

		public virtual int getLayers()
		{
			return layers;
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
			v.add(new ASN1Integer(layers));
			v.add(treeDigest);

			return new DERSequence(v);
		}
	}

}