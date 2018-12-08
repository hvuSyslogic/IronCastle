namespace org.bouncycastle.openssl
{

	using JcaMiscPEMGenerator = org.bouncycastle.openssl.jcajce.JcaMiscPEMGenerator;
	using PemGenerationException = org.bouncycastle.util.io.pem.PemGenerationException;
	using PemObjectGenerator = org.bouncycastle.util.io.pem.PemObjectGenerator;
	using PemWriter = org.bouncycastle.util.io.pem.PemWriter;

	/// <summary>
	/// General purpose writer for OpenSSL PEM objects. </summary>
	/// @deprecated use JcaPEMWriter 
	public class PEMWriter : PemWriter
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="out"> output stream to use. </param>
		public PEMWriter(Writer @out) : base(@out)
		{
		}

		/// <exception cref="IOException"> </exception>
		public virtual void writeObject(object obj)
		{
			writeObject(obj, null);
		}

		/// <param name="obj"> </param>
		/// <param name="encryptor"> </param>
		/// <exception cref="IOException"> </exception>
		public virtual void writeObject(object obj, PEMEncryptor encryptor)
		{
			try
			{
				base.writeObject(new JcaMiscPEMGenerator(obj, encryptor));
			}
			catch (PemGenerationException e)
			{
				if (e.InnerException is IOException)
				{
					throw (IOException)e.InnerException;
				}

				throw e;
			}
		}

		public override void writeObject(PemObjectGenerator obj)
		{
			base.writeObject(obj);
		}
	}

}