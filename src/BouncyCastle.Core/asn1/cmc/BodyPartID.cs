using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.cmc
{


	/// <summary>
	/// <pre>
	///       bodyIdMax INTEGER ::= 4294967295
	/// 
	///       BodyPartID ::= INTEGER(0..bodyIdMax)
	/// </pre>
	/// </summary>
	public class BodyPartID : ASN1Object
	{
		public const long bodyIdMax = 4294967295L;

		private readonly long id;

		public BodyPartID(long id)
		{
			if (id < 0 || id > bodyIdMax)
			{
				throw new IllegalArgumentException("id out of range");
			}

			this.id = id;
		}

		private static long convert(BigInteger value)
		{
			if (value.bitLength() > 32)
			{
				throw new IllegalArgumentException("id out of range");
			}
			return value.longValue();
		}

		private BodyPartID(ASN1Integer id) : this(convert(id.getValue()))
		{
		}

		public static BodyPartID getInstance(object o)
		{
			if (o is BodyPartID)
			{
				return (BodyPartID)o;
			}

			if (o != null)
			{
				return new BodyPartID(ASN1Integer.getInstance(o));
			}

			return null;
		}

		public virtual long getID()
		{
			return id;
		}

		public override ASN1Primitive toASN1Primitive()
		{
			return new ASN1Integer(id);
		}
	}

}