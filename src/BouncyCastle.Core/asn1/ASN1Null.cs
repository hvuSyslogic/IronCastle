/// <summary>
///************************************************************ </summary>
/// <summary>
///****    DO NOT EDIT THIS CLASS bc-java SOURCE FILE     ***** </summary>
/// <summary>
///************************************************************ </summary>

using System.IO;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;

namespace org.bouncycastle.asn1
{

	/// <summary>
	/// A NULL object - use DERNull.INSTANCE for populating structures.
	/// </summary>
	public abstract class ASN1Null : ASN1Primitive
	{
		public ASN1Null()
		{

		}

		/// <summary>
		/// Return an instance of ASN.1 NULL from the passed in object.
		/// <para>
		/// Accepted inputs:
		/// <ul>
		/// <li> null &rarr; null
		/// <li> <seealso cref="ASN1Null"/> object
		/// <li> a byte[] containing ASN.1 NULL object
		/// </ul>
		/// </para>
		/// </summary>
		/// <param name="o"> object to be converted. </param>
		/// <returns> an instance of ASN1Null, or null. </returns>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static ASN1Null getInstance(object o)
		{
			if (o is ASN1Null)
			{
				return (ASN1Null)o;
			}

			if (o != null)
			{
				try
				{
					return ASN1Null.getInstance(ASN1Primitive.fromByteArray((byte[])o));
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("failed to construct NULL from byte[]: " + e.Message);
				}
				catch (ClassCastException)
				{
					throw new IllegalArgumentException("unknown object in getInstance(): " + o.GetType().getName());
				}
			}

			return null;
		}

		public override int GetHashCode()
		{
			return -1;
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (!(o is ASN1Null))
			{
				return false;
			}

			return true;
		}

		public override abstract void encode(ASN1OutputStream @out);

		public override string ToString()
		{
			 return "NULL";
		}
	}

}