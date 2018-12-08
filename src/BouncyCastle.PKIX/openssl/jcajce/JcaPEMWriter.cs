namespace org.bouncycastle.openssl.jcajce
{

	using PemGenerationException = org.bouncycastle.util.io.pem.PemGenerationException;
	using PemObjectGenerator = org.bouncycastle.util.io.pem.PemObjectGenerator;
	using PemWriter = org.bouncycastle.util.io.pem.PemWriter;

	/// <summary>
	/// General purpose writer for OpenSSL PEM objects based on JCA/JCE classes.
	/// </summary>
	public class JcaPEMWriter : PemWriter
	{
		/// <summary>
		/// Base constructor.
		/// </summary>
		/// <param name="out"> output stream to use. </param>
		public JcaPEMWriter(Writer @out) : base(@out)
		{
		}

		/// <exception cref="java.io.IOException"> </exception>
		public virtual void writeObject(object obj)
		{
			writeObject(obj, null);
		}

		/// <param name="obj"> </param>
		/// <param name="encryptor"> </param>
		/// <exception cref="java.io.IOException"> </exception>
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