using BouncyCastle.Core.Port;
using org.bouncycastle.Port.java.util;

namespace org.bouncycastle.crypto.tls
{

	using DHStandardGroups = org.bouncycastle.crypto.agreement.DHStandardGroups;
	using DHParameters = org.bouncycastle.crypto.@params.DHParameters;

	public class DefaultTlsDHVerifier : TlsDHVerifier
	{
		public const int DEFAULT_MINIMUM_PRIME_BITS = 2048;

		protected internal static readonly Vector DEFAULT_GROUPS = new Vector();

		private static void addDefaultGroup(DHParameters dhParameters)
		{
			DEFAULT_GROUPS.addElement(dhParameters);
		}

		static DefaultTlsDHVerifier()
		{
			addDefaultGroup(DHStandardGroups.rfc7919_ffdhe2048);
			addDefaultGroup(DHStandardGroups.rfc7919_ffdhe3072);
			addDefaultGroup(DHStandardGroups.rfc7919_ffdhe4096);
			addDefaultGroup(DHStandardGroups.rfc7919_ffdhe6144);
			addDefaultGroup(DHStandardGroups.rfc7919_ffdhe8192);

			addDefaultGroup(DHStandardGroups.rfc3526_1536);
			addDefaultGroup(DHStandardGroups.rfc3526_2048);
			addDefaultGroup(DHStandardGroups.rfc3526_3072);
			addDefaultGroup(DHStandardGroups.rfc3526_4096);
			addDefaultGroup(DHStandardGroups.rfc3526_6144);
			addDefaultGroup(DHStandardGroups.rfc3526_8192);
		}

		// Vector is (DHParameters)
		protected internal Vector groups;
		protected internal int minimumPrimeBits;

		/// <summary>
		/// Accept various standard DH groups with 'P' at least <seealso cref="#DEFAULT_MINIMUM_PRIME_BITS"/> bits.
		/// </summary>
		public DefaultTlsDHVerifier() : this(DEFAULT_MINIMUM_PRIME_BITS)
		{
		}

		/// <summary>
		/// Accept various standard DH groups with 'P' at least the specified number of bits.
		/// </summary>
		public DefaultTlsDHVerifier(int minimumPrimeBits) : this(DEFAULT_GROUPS, minimumPrimeBits)
		{
		}

		/// <summary>
		/// Accept a custom set of group parameters, subject to a minimum bitlength for 'P'.
		/// </summary>
		/// <param name="groups"> a <seealso cref="Vector"/> of acceptable <seealso cref="DHParameters"/>. </param>
		public DefaultTlsDHVerifier(Vector groups, int minimumPrimeBits)
		{
			this.groups = groups;
			this.minimumPrimeBits = minimumPrimeBits;
		}

		public virtual bool accept(DHParameters dhParameters)
		{
			return checkMinimumPrimeBits(dhParameters) && checkGroup(dhParameters);
		}

		public virtual int getMinimumPrimeBits()
		{
			return minimumPrimeBits;
		}

		public virtual bool areGroupsEqual(DHParameters a, DHParameters b)
		{
			return a == b || (areParametersEqual(a.getP(), b.getP()) && areParametersEqual(a.getG(), b.getG()));
		}

		public virtual bool areParametersEqual(BigInteger a, BigInteger b)
		{
			return a == b || a.Equals(b);
		}

		public virtual bool checkGroup(DHParameters dhParameters)
		{
			for (int i = 0; i < groups.size(); ++i)
			{
				if (areGroupsEqual(dhParameters, (DHParameters)groups.elementAt(i)))
				{
					return true;
				}
			}
			return false;
		}

		public virtual bool checkMinimumPrimeBits(DHParameters dhParameters)
		{
			return dhParameters.getP().bitLength() >= getMinimumPrimeBits();
		}
	}

}