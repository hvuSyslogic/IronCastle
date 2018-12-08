using BouncyCastle.Core.Port;

namespace org.bouncycastle.crypto.tls
{

	using SRP6VerifierGenerator = org.bouncycastle.crypto.agreement.srp.SRP6VerifierGenerator;
	using HMac = org.bouncycastle.crypto.macs.HMac;
	using KeyParameter = org.bouncycastle.crypto.@params.KeyParameter;
	using SRP6GroupParameters = org.bouncycastle.crypto.@params.SRP6GroupParameters;
	using Strings = org.bouncycastle.util.Strings;

	/// <summary>
	/// An implementation of <seealso cref="TlsSRPIdentityManager"/> that simulates the existence of "unknown" identities
	/// to obscure the fact that there is no verifier for them. 
	/// </summary>
	public class SimulatedTlsSRPIdentityManager : TlsSRPIdentityManager
	{
		private static readonly byte[] PREFIX_PASSWORD = Strings.toByteArray("password");
		private static readonly byte[] PREFIX_SALT = Strings.toByteArray("salt");

		/// <summary>
		/// Create a <seealso cref="SimulatedTlsSRPIdentityManager"/> that implements the algorithm from RFC 5054 2.5.1.3
		/// </summary>
		/// <param name="group"> the <seealso cref="SRP6GroupParameters"/> defining the group that SRP is operating in </param>
		/// <param name="seedKey"> the secret "seed key" referred to in RFC 5054 2.5.1.3 </param>
		/// <returns> an instance of <seealso cref="SimulatedTlsSRPIdentityManager"/> </returns>
		public static SimulatedTlsSRPIdentityManager getRFC5054Default(SRP6GroupParameters group, byte[] seedKey)
		{
			SRP6VerifierGenerator verifierGenerator = new SRP6VerifierGenerator();
			verifierGenerator.init(group, TlsUtils.createHash(HashAlgorithm.sha1));

			HMac mac = new HMac(TlsUtils.createHash(HashAlgorithm.sha1));
			mac.init(new KeyParameter(seedKey));

			return new SimulatedTlsSRPIdentityManager(group, verifierGenerator, mac);
		}

		protected internal SRP6GroupParameters group;
		protected internal SRP6VerifierGenerator verifierGenerator;
		protected internal Mac mac;

		public SimulatedTlsSRPIdentityManager(SRP6GroupParameters group, SRP6VerifierGenerator verifierGenerator, Mac mac)
		{
			this.group = group;
			this.verifierGenerator = verifierGenerator;
			this.mac = mac;
		}

		public virtual TlsSRPLoginParameters getLoginParameters(byte[] identity)
		{
			mac.update(PREFIX_SALT, 0, PREFIX_SALT.Length);
			mac.update(identity, 0, identity.Length);

			byte[] salt = new byte[mac.getMacSize()];
			mac.doFinal(salt, 0);

			mac.update(PREFIX_PASSWORD, 0, PREFIX_PASSWORD.Length);
			mac.update(identity, 0, identity.Length);

			byte[] password = new byte[mac.getMacSize()];
			mac.doFinal(password, 0);

			BigInteger verifier = verifierGenerator.generateVerifier(salt, identity, password);

			return new TlsSRPLoginParameters(group, verifier, salt);
		}
	}

}