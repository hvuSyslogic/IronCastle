using System;
using org.bouncycastle.Port;
using org.bouncycastle.Port.java.io;
using org.bouncycastle.Port.java.lang;
using org.bouncycastle.Port.java.util;
using org.bouncycastle.util;

namespace org.bouncycastle.crypto.generators
{

		
	/// <summary>
	/// Password hashing scheme BCrypt,
	/// designed by Niels Provos and David Mazières, using the
	/// String format and the Base64 encoding
	/// of the reference implementation on OpenBSD
	/// </summary>
	public class OpenBSDBCrypt
	{
		private static readonly byte[] encodingTable = new byte[] {(byte)'.', (byte)'/', (byte)'A', (byte)'B', (byte)'C', (byte)'D', (byte)'E', (byte)'F', (byte)'G', (byte)'H', (byte)'I', (byte)'J', (byte)'K', (byte)'L', (byte)'M', (byte)'N', (byte)'O', (byte)'P', (byte)'Q', (byte)'R', (byte)'S', (byte)'T', (byte)'U', (byte)'V', (byte)'W', (byte)'X', (byte)'Y', (byte)'Z', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f', (byte)'g', (byte)'h', (byte)'i', (byte)'j', (byte)'k', (byte)'l', (byte)'m', (byte)'n', (byte)'o', (byte)'p', (byte)'q', (byte)'r', (byte)'s', (byte)'t', (byte)'u', (byte)'v', (byte)'w', (byte)'x', (byte)'y', (byte)'z', (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7', (byte)'8', (byte)'9'};
		/*
		 * set up the decoding table.
		 */
		private static readonly byte[] decodingTable = new byte[128];
		private const string defaultVersion = "2y";
		private static readonly Set<string> allowedVersions = new HashSet<string>();

		static OpenBSDBCrypt()
		{
			// Presently just the Bcrypt versions.
			allowedVersions.add("2a");
			allowedVersions.add("2y");
			allowedVersions.add("2b");

			for (int i = 0; i < decodingTable.Length; i++)
			{
				decodingTable[i] = unchecked(0xff);
			}

			for (int i = 0; i < encodingTable.Length; i++)
			{
				decodingTable[encodingTable[i]] = (byte)i;
			}
		}

		public OpenBSDBCrypt()
		{

		}

		/// <summary>
		/// Creates a 60 character Bcrypt String, including
		/// version, cost factor, salt and hash, separated by '$'
		/// </summary>
		/// <param name="version">  the version, 2y,2b or 2a. (2a is not backwards compatible.) </param>
		/// <param name="cost">     the cost factor, treated as an exponent of 2 </param>
		/// <param name="salt">     a 16 byte salt </param>
		/// <param name="password"> the password </param>
		/// <returns> a 60 character Bcrypt String </returns>
		private static string createBcryptString(string version, byte[] password, byte[] salt, int cost)
		{
			if (!allowedVersions.contains(version))
			{
				throw new IllegalArgumentException("Version " + version + " is not accepted by this implementation.");
			}

			StringBuffer sb = new StringBuffer(60);
			sb.append('$');
			sb.append(version);
			sb.append('$');
			sb.append(cost < 10 ? ("0" + cost) : Convert.ToString(cost));
			sb.append('$');
			sb.append(encodeData(salt));

			byte[] key = BCrypt.generate(password, salt, cost);

			sb.append(encodeData(key));

			return sb.ToString();
		}

		/// <summary>
		/// Creates a 60 character Bcrypt String, including
		/// version, cost factor, salt and hash, separated by '$' using version
		/// '2y'.
		/// </summary>
		/// <param name="cost">     the cost factor, treated as an exponent of 2 </param>
		/// <param name="salt">     a 16 byte salt </param>
		/// <param name="password"> the password </param>
		/// <returns> a 60 character Bcrypt String </returns>
		public static string generate(char[] password, byte[] salt, int cost)
		{
			return generate(defaultVersion, password, salt, cost);
		}


		/// <summary>
		/// Creates a 60 character Bcrypt String, including
		/// version, cost factor, salt and hash, separated by '$'
		/// </summary>
		/// <param name="version">  the version, may be 2b, 2y or 2a. (2a is not backwards compatible.) </param>
		/// <param name="cost">     the cost factor, treated as an exponent of 2 </param>
		/// <param name="salt">     a 16 byte salt </param>
		/// <param name="password"> the password </param>
		/// <returns> a 60 character Bcrypt String </returns>
		public static string generate(string version, char[] password, byte[] salt, int cost)
		{
			if (!allowedVersions.contains(version))
			{
				throw new IllegalArgumentException("Version " + version + " is not accepted by this implementation.");
			}

			if (password == null)
			{
				throw new IllegalArgumentException("Password required.");
			}
			if (salt == null)
			{
				throw new IllegalArgumentException("Salt required.");
			}
			else if (salt.Length != 16)
			{
				throw new DataLengthException("16 byte salt required: " + salt.Length);
			}
			if (cost < 4 || cost > 31) // Minimum rounds: 16, maximum 2^31
			{
				throw new IllegalArgumentException("Invalid cost factor.");
			}

			byte[] psw = Strings.toUTF8ByteArray(password);

			// 0 termination:

			byte[] tmp = new byte[psw.Length >= 72 ? 72 : psw.Length + 1];

			if (tmp.Length > psw.Length)
			{
				JavaSystem.arraycopy(psw, 0, tmp, 0, psw.Length);
			}
			else
			{
				JavaSystem.arraycopy(psw, 0, tmp, 0, tmp.Length);
			}

			Arrays.fill(psw, 0);

			string rv = createBcryptString(version, tmp, salt, cost);

			Arrays.fill(tmp, 0);

			return rv;
		}

		/// <summary>
		/// Checks if a password corresponds to a 60 character Bcrypt String
		/// </summary>
		/// <param name="bcryptString"> a 60 character Bcrypt String, including
		///                     version, cost factor, salt and hash,
		///                     separated by '$' </param>
		/// <param name="password">     the password as an array of chars </param>
		/// <returns> true if the password corresponds to the
		/// Bcrypt String, otherwise false </returns>
		public static bool checkPassword(string bcryptString, char[] password)
		{
			// validate bcryptString:
			if (bcryptString.Length != 60)
			{
				throw new DataLengthException("Bcrypt String length: " + bcryptString.Length + ", 60 required.");
			}

			if (bcryptString[0] != '$' || bcryptString[3] != '$' || bcryptString[6] != '$')
			{
				throw new IllegalArgumentException("Invalid Bcrypt String format.");
			}

			string version = bcryptString.Substring(1, 2);

			if (!allowedVersions.contains(version))
			{
				throw new IllegalArgumentException("Bcrypt version '" + version + "' is not supported by this implementation");
			}

			int cost = 0;
			string costStr = bcryptString.Substring(4, 2);
			try
			{
				cost = int.Parse(costStr);
			}
			catch (NumberFormatException)
			{
				throw new IllegalArgumentException("Invalid cost factor: " + costStr);
			}
			if (cost < 4 || cost > 31)
			{
				throw new IllegalArgumentException("Invalid cost factor: " + cost + ", 4 < cost < 31 expected.");
			}
			// check password:
			if (password == null)
			{
				throw new IllegalArgumentException("Missing password.");
			}
			byte[] salt = decodeSaltString(StringHelper.SubstringSpecial(bcryptString, bcryptString.LastIndexOf('$') + 1, bcryptString.Length - 31));

			string newBcryptString = generate(version, password, salt, cost);

			return bcryptString.Equals(newBcryptString);
		}

		/*
		 * encode the input data producing a Bcrypt base 64 String.
		 *
		 * @param 	a byte representation of the salt or the password
		 * @return 	the Bcrypt base64 String
		 */
		private static string encodeData(byte[] data)

		{
			if (data.Length != 24 && data.Length != 16) // 192 bit key or 128 bit salt expected
			{
				throw new DataLengthException("Invalid length: " + data.Length + ", 24 for key or 16 for salt expected");
			}
			bool salt = false;
			if (data.Length == 16) //salt
			{
				salt = true;
				byte[] tmp = new byte[18]; // zero padding
				JavaSystem.arraycopy(data, 0, tmp, 0, data.Length);
				data = tmp;
			}
			else // key
			{
				data[data.Length - 1] = 0;
			}

			ByteArrayOutputStream @out = new ByteArrayOutputStream();
			int len = data.Length;

			int a1, a2, a3;
			int i;
			for (i = 0; i < len; i += 3)
			{
				a1 = data[i] & 0xff;
				a2 = data[i + 1] & 0xff;
				a3 = data[i + 2] & 0xff;

				@out.write(encodingTable[((int)((uint)a1 >> 2)) & 0x3f]);
				@out.write(encodingTable[((a1 << 4) | ((int)((uint)a2 >> 4))) & 0x3f]);
				@out.write(encodingTable[((a2 << 2) | ((int)((uint)a3 >> 6))) & 0x3f]);
				@out.write(encodingTable[a3 & 0x3f]);
			}

			string result = Strings.fromByteArray(@out.toByteArray());
			if (salt == true) // truncate padding
			{
				return result.Substring(0, 22);
			}
			else
			{
				return result.Substring(0, result.Length - 1);
			}
		}


		/*
		 * decodes the bcrypt base 64 encoded SaltString
		 *
		 * @param 		a 22 character Bcrypt base 64 encoded String 
		 * @return 		the 16 byte salt
		 * @exception 	DataLengthException if the length 
		 * 				of parameter is not 22
		 * @exception 	InvalidArgumentException if the parameter
		 * 				contains a value other than from Bcrypts base 64 encoding table
		 */
		private static byte[] decodeSaltString(string saltString)
		{
			char[] saltChars = saltString.ToCharArray();

			ByteArrayOutputStream @out = new ByteArrayOutputStream(16);
			byte b1, b2, b3, b4;

			if (saltChars.Length != 22) // bcrypt salt must be 22 (16 bytes)
			{
				throw new DataLengthException("Invalid base64 salt length: " + saltChars.Length + " , 22 required.");
			}

			// check String for invalid characters:
			for (int i = 0; i < saltChars.Length; i++)
			{
				int value = saltChars[i];
				if (value > 122 || value < 46 || (value > 57 && value < 65))
				{
					throw new IllegalArgumentException("Salt string contains invalid character: " + value);
				}
			}

			// Padding: add two '\u0000'
			char[] tmp = new char[22 + 2];
			JavaSystem.arraycopy(saltChars, 0, tmp, 0, saltChars.Length);
			saltChars = tmp;

			int len = saltChars.Length;

			for (int i = 0; i < len; i += 4)
			{
				b1 = decodingTable[saltChars[i]];
				b2 = decodingTable[saltChars[i + 1]];
				b3 = decodingTable[saltChars[i + 2]];
				b4 = decodingTable[saltChars[i + 3]];

				@out.write((b1 << 2) | (b2 >> 4));
				@out.write((b2 << 4) | (b3 >> 2));
				@out.write((b3 << 6) | b4);
			}

			byte[] saltBytes = @out.toByteArray();

			// truncate:
			byte[] tmpSalt = new byte[16];
			JavaSystem.arraycopy(saltBytes, 0, tmpSalt, 0, tmpSalt.Length);
			saltBytes = tmpSalt;

			return saltBytes;
		}
	}
}