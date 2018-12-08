using BouncyCastle.Core.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1.x9
{


	/// <summary>
	/// X9.42 definition of a DHPublicKey
	/// <pre>
	///     DHPublicKey ::= INTEGER
	/// </pre>
	/// </summary>
	public class DHPublicKey : ASN1Object
	{
		private ASN1Integer y;

		/// <summary>
		/// Return a DHPublicKey from the passed in tagged object.
		/// </summary>
		/// <param name="obj"> a tagged object. </param>
		/// <param name="explicit"> true if the contents of the object is explictly tagged, false otherwise. </param>
		/// <returns> a DHPublicKey </returns>
		public static DHPublicKey getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			return getInstance(ASN1Integer.getInstance(obj, @explicit));
		}

		/// <summary>
		/// Return a DHPublicKey from the passed in object.
		/// </summary>
		/// <param name="obj"> an object for conversion or a byte[]. </param>
		/// <returns> a DHPublicKey </returns>
		public static DHPublicKey getInstance(object obj)
		{
			if (obj == null || obj is DHPublicKey)
			{
				return (DHPublicKey)obj;
			}

			if (obj is ASN1Integer)
			{
				return new DHPublicKey((ASN1Integer)obj);
			}

			throw new IllegalArgumentException("Invalid DHPublicKey: " + obj.GetType().getName());
		}

		private DHPublicKey(ASN1Integer y)
		{
			if (y == null)
			{
				throw new IllegalArgumentException("'y' cannot be null");
			}

			this.y = y;
		}

		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="y"> the public value Y. </param>
		public DHPublicKey(BigInteger y)
		{
			if (y == null)
			{
				throw new IllegalArgumentException("'y' cannot be null");
			}

			this.y = new ASN1Integer(y);
		}

		/// <summary>
		/// Return the public value Y for the key.
		/// </summary>
		/// <returns> the Y value. </returns>
		public virtual BigInteger getY()
		{
			return this.y.getPositiveValue();
		}

		/// <summary>
		/// Return an ASN.1 primitive representation of this object.
		/// </summary>
		/// <returns> an ASN1Integer. </returns>
		public override ASN1Primitive toASN1Primitive()
		{
			return this.y;
		}
	}
}