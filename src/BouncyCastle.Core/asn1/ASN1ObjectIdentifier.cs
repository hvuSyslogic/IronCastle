using System;
using System.IO;
using BouncyCastle.Core.Port;
using org.bouncycastle.Port;
using org.bouncycastle.Port.Extensions;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util.concurrent;

namespace org.bouncycastle.asn1
{

	using Arrays = org.bouncycastle.util.Arrays;

	/// <summary>
	/// Class representing the ASN.1 OBJECT IDENTIFIER type.
	/// </summary>
	public class ASN1ObjectIdentifier : ASN1Primitive
	{
		private readonly string identifier;

		private byte[] body;

		/// <summary>
		/// Return an OID from the passed in object
		/// </summary>
		/// <param name="obj"> an ASN1ObjectIdentifier or an object that can be converted into one. </param>
		/// <returns> an ASN1ObjectIdentifier instance, or null. </returns>
		/// <exception cref="IllegalArgumentException"> if the object cannot be converted. </exception>
		public static ASN1ObjectIdentifier getInstance(object obj)
		{
			if (obj == null || obj is ASN1ObjectIdentifier)
			{
				return (ASN1ObjectIdentifier)obj;
			}

			if (obj is ASN1Encodable && ((ASN1Encodable)obj).toASN1Primitive() is ASN1ObjectIdentifier)
			{
				return (ASN1ObjectIdentifier)((ASN1Encodable)obj).toASN1Primitive();
			}

			if (obj is byte[])
			{
				byte[] enc = (byte[])obj;
				try
				{
					return (ASN1ObjectIdentifier)fromByteArray(enc);
				}
				catch (IOException e)
				{
					throw new IllegalArgumentException("failed to construct object identifier from byte[]: " + e.Message);
				}
			}

			throw new IllegalArgumentException("illegal object in getInstance: " + obj.GetType().getName());
		}

		/// <summary>
		/// Return an OBJECT IDENTIFIER from a tagged object.
		/// </summary>
		/// <param name="obj">      the tagged object holding the object we want </param>
		/// <param name="explicit"> true if the object is meant to be explicitly
		///                 tagged false otherwise. </param>
		/// <returns> an ASN1ObjectIdentifier instance, or null. </returns>
		/// <exception cref="IllegalArgumentException"> if the tagged object cannot
		/// be converted. </exception>
		public static ASN1ObjectIdentifier getInstance(ASN1TaggedObject obj, bool @explicit)
		{
			ASN1Primitive o = obj.getObject();

			if (@explicit || o is ASN1ObjectIdentifier)
			{
				return getInstance(o);
			}
			else
			{
				return ASN1ObjectIdentifier.fromOctetString(ASN1OctetString.getInstance(o).getOctets());
			}
		}

		private static readonly long LONG_LIMIT = (long.MaxValue >> 7) - 0x7f;

		public ASN1ObjectIdentifier(byte[] bytes)
		{
			StringBuffer objId = new StringBuffer();
			long value = 0;
			BigInteger bigValue = null;
			bool first = true;

			for (int i = 0; i != bytes.Length; i++)
			{
				int b = bytes[i] & 0xff;

				if (value <= LONG_LIMIT)
				{
					value += (b & 0x7f);
					if ((b & 0x80) == 0) // end of number reached
					{
						if (first)
						{
							if (value < 40)
							{
								objId.append('0');
							}
							else if (value < 80)
							{
								objId.append('1');
								value -= 40;
							}
							else
							{
								objId.append('2');
								value -= 80;
							}
							first = false;
						}

						objId.append('.');
						objId.append(value);
						value = 0;
					}
					else
					{
						value <<= 7;
					}
				}
				else
				{
					if (bigValue == null)
					{
						bigValue = BigInteger.valueOf(value);
					}
					bigValue = bigValue.or(BigInteger.valueOf(b & 0x7f));
					if ((b & 0x80) == 0)
					{
						if (first)
						{
							objId.append('2');
							bigValue = bigValue.subtract(BigInteger.valueOf(80));
							first = false;
						}

						objId.append('.');
						objId.append(bigValue);
						bigValue = null;
						value = 0;
					}
					else
					{
						bigValue = bigValue.shiftLeft(7);
					}
				}
			}

			this.identifier = objId.ToString();
			this.body = Arrays.clone(bytes);
		}

		/// <summary>
		/// Create an OID based on the passed in String.
		/// </summary>
		/// <param name="identifier"> a string representation of an OID. </param>
		public ASN1ObjectIdentifier(string identifier)
		{
			if (string.ReferenceEquals(identifier, null))
			{
				throw new IllegalArgumentException("'identifier' cannot be null");
			}
			if (!isValidIdentifier(identifier))
			{
				throw new IllegalArgumentException("string " + identifier + " not an OID");
			}

			this.identifier = identifier;
		}

		/// <summary>
		/// Create an OID that creates a branch under the current one.
		/// </summary>
		/// <param name="branchID"> node numbers for the new branch. </param>
		/// <returns> the OID for the new created branch. </returns>
		public ASN1ObjectIdentifier(ASN1ObjectIdentifier oid, string branchID)
		{
			if (!isValidBranchID(branchID, 0))
			{
				throw new IllegalArgumentException("string " + branchID + " not a valid OID branch");
			}

			this.identifier = oid.getId() + "." + branchID;
		}

		/// <summary>
		/// Return the OID as a string.
		/// </summary>
		/// <returns> the string representation of the OID carried by this object. </returns>
		public virtual string getId()
		{
			return identifier;
		}

		/// <summary>
		/// Return an OID that creates a branch under the current one.
		/// </summary>
		/// <param name="branchID"> node numbers for the new branch. </param>
		/// <returns> the OID for the new created branch. </returns>
		public virtual ASN1ObjectIdentifier branch(string branchID)
		{
			return new ASN1ObjectIdentifier(this, branchID);
		}

		/// <summary>
		/// Return true if this oid is an extension of the passed in branch - stem.
		/// </summary>
		/// <param name="stem"> the arc or branch that is a possible parent. </param>
		/// <returns> true if the branch is on the passed in stem, false otherwise. </returns>
		public virtual bool on(ASN1ObjectIdentifier stem)
		{
			string id = getId(), stemId = stem.getId();
			return id.Length > stemId.Length && id[stemId.Length] == '.' && id.StartsWith(stemId, StringComparison.Ordinal);
		}

		private void writeField(ByteArrayOutputStream @out, long fieldValue)
		{
			byte[] result = new byte[9];
			int pos = 8;
			result[pos] = (byte)((int)fieldValue & 0x7f);
			while (fieldValue >= (1L << 7))
			{
				fieldValue >>= 7;
				result[--pos] = unchecked((byte)((int)fieldValue & 0x7f | 0x80));
			}
			@out.write(result, pos, 9 - pos);
		}

		private void writeField(ByteArrayOutputStream @out, BigInteger fieldValue)
		{
			int byteCount = (fieldValue.bitLength() + 6) / 7;
			if (byteCount == 0)
			{
				@out.write(0);
			}
			else
			{
				BigInteger tmpValue = fieldValue;
				byte[] tmp = new byte[byteCount];
				for (int i = byteCount - 1; i >= 0; i--)
				{
					tmp[i] = unchecked((byte)((tmpValue.intValue() & 0x7f) | 0x80));
					tmpValue = tmpValue.shiftRight(7);
				}
				tmp[byteCount - 1] &= 0x7f;
				@out.write(tmp, 0, tmp.Length);
			}
		}

		private void doOutput(ByteArrayOutputStream aOut)
		{
			OIDTokenizer tok = new OIDTokenizer(identifier);
			int first = int.Parse(tok.nextToken()) * 40;

			string secondToken = tok.nextToken();
			if (secondToken.Length <= 18)
			{
				writeField(aOut, first + long.Parse(secondToken));
			}
			else
			{
				writeField(aOut, (new BigInteger(secondToken)).add(BigInteger.valueOf(first)));
			}

			while (tok.hasMoreTokens())
			{
				string token = tok.nextToken();
				if (token.Length <= 18)
				{
					writeField(aOut, long.Parse(token));
				}
				else
				{
					writeField(aOut, new BigInteger(token));
				}
			}
		}

		private byte[] getBody()
		{
			lock (this)
			{
				if (body == null)
				{
					ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        
					doOutput(bOut);
        
					body = bOut.toByteArray();
				}
        
				return body;
			}
		}

		public override bool isConstructed()
		{
			return false;
		}

		public override int encodedLength()
		{
			int length = getBody().Length;

			return 1 + StreamUtil.calculateBodyLength(length) + length;
		}

		public override void encode(ASN1OutputStream @out)
		{
			byte[] enc = getBody();

			@out.write(BERTags_Fields.OBJECT_IDENTIFIER);
			@out.writeLength(enc.Length);
			@out.write(enc);
		}

		public override int GetHashCode()
		{
			return identifier.GetHashCode();
		}

		public override bool asn1Equals(ASN1Primitive o)
		{
			if (o == this)
			{
				return true;
			}

			if (!(o is ASN1ObjectIdentifier))
			{
				return false;
			}

			return identifier.Equals(((ASN1ObjectIdentifier)o).identifier);
		}

		public override string ToString()
		{
			return getId();
		}

		private static bool isValidBranchID(string branchID, int start)
		{
			bool periodAllowed = false;

			int pos = branchID.Length;
			while (--pos >= start)
			{
				char ch = branchID[pos];

				// TODO Leading zeroes?
				if ('0' <= ch && ch <= '9')
				{
					periodAllowed = true;
					continue;
				}

				if (ch == '.')
				{
					if (!periodAllowed)
					{
						return false;
					}

					periodAllowed = false;
					continue;
				}

				return false;
			}

			return periodAllowed;
		}

		private static bool isValidIdentifier(string identifier)
		{
			if (identifier.Length < 3 || identifier[1] != '.')
			{
				return false;
			}

			char first = identifier[0];
			if (first < '0' || first > '2')
			{
				return false;
			}

			return isValidBranchID(identifier, 2);
		}

		/// <summary>
		/// Intern will return a reference to a pooled version of this object, unless it
		/// is not present in which case intern will add it.
		/// <para>
		/// The pool is also used by the ASN.1 parsers to limit the number of duplicated OID
		/// objects in circulation.
		/// </para>
		/// </summary>
		/// <returns> a reference to the identifier in the pool. </returns>
		public virtual ASN1ObjectIdentifier intern()
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final OidHandle hdl = new OidHandle(getBody());
			OidHandle hdl = new OidHandle(getBody());
			ASN1ObjectIdentifier oid = pool.get(hdl);
			if (oid == null)
			{
				oid = pool.putIfAbsent(hdl, this);
				if (oid == null)
				{
					oid = this;
				}
			}
			return oid;
		}

		private static readonly ConcurrentMap<OidHandle, ASN1ObjectIdentifier> pool = new ConcurrentHashMap<OidHandle, ASN1ObjectIdentifier>();

		public class OidHandle
		{
			internal readonly int key;
			internal readonly byte[] enc;

			public OidHandle(byte[] enc)
			{
				this.key = Arrays.GetHashCode(enc);
				this.enc = enc;
			}

			public override int GetHashCode()
			{
				return key;
			}

			public override bool Equals(object o)
			{
				if (o is OidHandle)
				{
					return Arrays.areEqual(enc, ((OidHandle)o).enc);
				}

				return false;
			}
		}

		internal static ASN1ObjectIdentifier fromOctetString(byte[] enc)
		{
//JAVA TO C# CONVERTER WARNING: The original Java variable was marked 'final':
//ORIGINAL LINE: final OidHandle hdl = new OidHandle(enc);
			OidHandle hdl = new OidHandle(enc);
			ASN1ObjectIdentifier oid = pool.get(hdl);
			if (oid == null)
			{
				return new ASN1ObjectIdentifier(enc);
			}
			return oid;
		}
	}

}