using System.IO;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.util;

namespace org.bouncycastle.asn1
{

	
	/// <summary>
	/// Public facade of ASN.1 Boolean data.
	/// <para>
	/// Use following to place a new instance of ASN.1 Boolean in your dataset:
	/// <ul>
	/// <li> ASN1Boolean.TRUE literal</li>
	/// <li> ASN1Boolean.FALSE literal</li>
	/// <li> <seealso cref="ASN1Boolean#getInstance(boolean) ASN1Boolean.getInstance(boolean)"/></li>
	/// <li> <seealso cref="ASN1Boolean#getInstance(int) ASN1Boolean.getInstance(int)"/></li>
	/// </ul>
	/// </para>
	/// </summary>
	public class ASN1Boolean : ASN1Primitive
	{
		private static readonly byte[] TRUE_VALUE = new byte[] {unchecked(0xff)};
		private static readonly byte[] FALSE_VALUE = new byte[] {0};

		private readonly byte[] value;

		public static readonly ASN1Boolean FALSE = new ASN1Boolean(false);
		public static readonly ASN1Boolean TRUE = new ASN1Boolean(true);

		/// <summary>
		/// Return a boolean from the passed in object.
		/// </summary>
		/// <param name="obj"> an ASN1Boolean or an object that can be converted into one. </param>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		/// <returns> an ASN1Boolean instance. </returns>
		public static ASN1Boolean getInstance(object obj)
		{
			if (obj == null || obj is ASN1Boolean)
			{
				return (ASN1Boolean)obj;
			}

			if (obj is byte[])
			{
				byte[] enc = (byte[])obj;
				try
				{
					return (ASN1Boolean)fromByteArray(enc);
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("failed to construct boolean from byte[]: " + e.Message);
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an ASN1Boolean from the passed in boolean. </summary>
		/// <param name="value"> true or false depending on the ASN1Boolean wanted. </param>
		/// <returns> an ASN1Boolean instance. </returns>
		public static ASN1Boolean getInstance(bool value)
		{
			return (value ? TRUE : FALSE);
		}

		/// <summary>
		/// Return an ASN1Boolean from the passed in value. </summary>
		/// <param name="value"> non-zero (true) or zero (false) depending on the ASN1Boolean wanted. </param>
		/// <returns> an ASN1Boolean instance. </returns>
		public static ASN1Boolean getInstance(int value)
		{
			return (value != 0 ? TRUE : FALSE);
		}

		/// <summary>
		/// Return a Boolean from a tagged object.
		/// </summary>
		/// <param name="obj"> the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///              tagged false otherwise. </param>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		///               be converted. </exception>
		/// <returns> an ASN1Boolean instance. </returns>
		public static ASN1Boolean getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is ASN1Boolean)
			{
				return getInstance(o);
			}
			else
			{
				return ASN1Boolean.fromOctetString(((ASN1OctetString)o).getOctets());
			}
		}

		public ASN1Boolean(byte[] value)
		{
			if (value.Length != 1)
			{
				throw new IllegalArgumentException("byte value should have 1 byte in it");
			}

			if (value[0] == 0)
			{
				this.value = FALSE_VALUE;
			}
			else if ((value[0] & 0xff) == 0xff)
			{
				this.value = TRUE_VALUE;
			}
			else
			{
				this.value = Arrays.clone(value);
			}
		}

		/// @deprecated use getInstance(boolean) method. 
		/// <param name="value"> true or false. </param>
		public ASN1Boolean(bool value)
		{
			this.value = (value) ? TRUE_VALUE : FALSE_VALUE;
		}

		public virtual bool isTrue()
		{
			return (value[0] != 0);
		}

		public override bool isConstructed()
		{
			return false;
		}

		public override int encodedLength()
		{
			return 3;
		}

		public override void encode(ASN1OutputStream @out)
		{
			@out.writeEncoded(BERTags_Fields.BOOLEAN, value);
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (o is ASN1Boolean)
			{
				return (value[0] == ((ASN1Boolean)o).value[0]);
			}

			return false;
		}

		public override int GetHashCode()
		{
			return value[0];
		}


		public override string ToString()
		{
		  return (value[0] != 0) ? "TRUE" : "FALSE";
		}

		internal static ASN1Boolean fromOctetString(byte[] value)
		{
			if (value.Length != 1)
			{
				throw new IllegalArgumentException("BOOLEAN value should have 1 byte in it");
			}

			if (value[0] == 0)
			{
				return FALSE;
			}
			else if ((value[0] & 0xff) == 0xff)
			{
				return TRUE;
			}
			else
			{
				return new ASN1Boolean(value);
			}
		}
	}

}