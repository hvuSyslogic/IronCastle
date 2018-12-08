using System;

namespace org.bouncycastle.jce.spec
{

	using Arrays = org.bouncycastle.util.Arrays;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// Holds an OpenSSH encoded public key.
	/// </summary>
	public class OpenSSHPublicKeySpec : EncodedKeySpec
	{
		private static readonly string[] allowedTypes = new string[]{"ssh-rsa", "ssh-ed25519", "ssh-dss"};
		private readonly string type;


		/// <summary>
		/// Construct and instance and determine the OpenSSH public key type.
		/// The current types are ssh-rsa, ssh-ed25519, ssh-dss and ecdsa-*
		/// <para>
		/// It does not validate the key beyond identifying the type.
		/// 
		/// </para>
		/// </summary>
		/// <param name="encodedKey"> </param>
		public OpenSSHPublicKeySpec(byte[] encodedKey) : base(encodedKey)
		{

			//
			// The type is encoded at the start of the blob.
			//
			int pos = 0;
			int i = (encodedKey[pos++] & 0xFF) << 24;
			i |= (encodedKey[pos++] & 0xFF) << 16;
			i |= (encodedKey[pos++] & 0xFF) << 8;
			i |= (encodedKey[pos++] & 0xFF);

			if ((pos + i) >= encodedKey.Length)
			{
				throw new IllegalArgumentException("invalid public key blob: type field longer than blob");
			}

			this.type = Strings.fromByteArray(Arrays.copyOfRange(encodedKey, pos, pos + i));

			if (type.StartsWith("ecdsa", StringComparison.Ordinal))
			{
				return; // These have a curve name and digest in them and can't be compared exactly.
			}

			for (int t = 0; t < allowedTypes.Length; t++)
			{
				if (allowedTypes[t].Equals(this.type))
				{
					return;
				}
			}

			throw new IllegalArgumentException("unrecognised public key type " + type);

		}

		public virtual string getFormat()
		{
			return "OpenSSH";
		}

		/// <summary>
		/// The type of OpenSSH public key.
		/// </summary>
		/// <returns> the type. </returns>
		public virtual string getType()
		{
			return type;
		}
	}

}