using org.bouncycastle.Port;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1.bc
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// <pre>
	/// ObjectDataSequence ::= SEQUENCE OF ObjectData
	/// </pre>
	/// </summary>
	public class ObjectDataSequence : ASN1Object, Iterable<ASN1Encodable>
	{
		private readonly ASN1Encodable[] dataSequence;

		public ObjectDataSequence(ObjectData[] dataSequence)
		{
			this.dataSequence = new ASN1Encodable[dataSequence.Length];

			JavaSystem.arraycopy(dataSequence, 0, this.dataSequence, 0, dataSequence.Length);
		}

		private ObjectDataSequence(ASN1Sequence seq)
		{
			dataSequence = new ASN1Encodable[seq.size()];

			for (int i = 0; i != dataSequence.Length; i++)
			{
				dataSequence[i] = ObjectData.getInstance(seq.getObjectAt(i));
			}
		}

		public static ObjectDataSequence getInstance(object obj)
		{
			if (obj is ObjectDataSequence)
			{
				return (ObjectDataSequence)obj;
			}
			else if (obj != null)
			{
				return new ObjectDataSequence(ASN1Sequence.getInstance(obj));
			}

			return null;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new DERSequence(dataSequence);
		}

		public virtual Iterator<ASN1Encodable> iterator()
		{
			return new Arrays.Iterator<ASN1Encodable>(dataSequence);
		}
	}

}