namespace org.bouncycastle.x509
{
	using StreamParser = org.bouncycastle.x509.util.StreamParser;
	using StreamParsingException = org.bouncycastle.x509.util.StreamParsingException;


	/// 
	/// <summary>
	/// This class allows access to different implementations for reading X.509
	/// objects from streams.
	/// <para>
	/// A X509StreamParser is used to read a collection of objects or a single object
	/// of a certain X.509 object structure. E.g. one X509StreamParser can read
	/// certificates, another one CRLs, certification paths, attribute certificates
	/// and so on. The kind of object structure is specified with the
	/// <code>algorithm</code> parameter to the <code>getInstance</code> methods.
	/// </para>
	/// <para>
	/// Implementations must implement the
	/// <seealso cref="org.bouncycastle.x509.X509StreamParserSpi"/>.
	/// </para>
	/// </summary>
	public class X509StreamParser : StreamParser
	{
		/// <summary>
		/// Generates a StreamParser object that implements the specified type. If
		/// the default provider package provides an implementation of the requested
		/// type, an instance of StreamParser containing that implementation is
		/// returned. If the type is not available in the default package, other
		/// packages are searched.
		/// </summary>
		/// <param name="type">
		///            The name of the requested X.509 object type. </param>
		/// <returns> a StreamParser object for the specified type.
		/// </returns>
		/// <exception cref="NoSuchParserException">
		///                if the requested type is not available in the default
		///                provider package or any of the other provider packages
		///                that were searched. </exception>
		public static X509StreamParser getInstance(string type)
		{
			try
			{
				X509Util.Implementation impl = X509Util.getImplementation("X509StreamParser", type);

				return createParser(impl);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new NoSuchParserException(e.Message);
			}
		}

		/// <summary>
		/// Generates a X509StreamParser object for the specified type from the
		/// specified provider.
		/// </summary>
		/// <param name="type">
		///            the name of the requested X.509 object type. </param>
		/// <param name="provider">
		///            the name of the provider.
		/// </param>
		/// <returns> a X509StreamParser object for the specified type.
		/// </returns>
		/// <exception cref="NoSuchParserException">
		///                if the type is not available from the specified provider.
		/// </exception>
		/// <exception cref="NoSuchProviderException">
		///                if the provider can not be found.
		/// </exception>
		/// <seealso cref= Provider </seealso>
		public static X509StreamParser getInstance(string type, string provider)
		{
			return getInstance(type, X509Util.getProvider(provider));
		}

		/// <summary>
		/// Generates a X509StreamParser object for the specified type from the
		/// specified provider.
		/// </summary>
		/// <param name="type">
		///            the name of the requested X.509 object type. </param>
		/// <param name="provider">
		///            the Provider to use.
		/// </param>
		/// <returns> a X509StreamParser object for the specified type.
		/// </returns>
		/// <exception cref="NoSuchParserException">
		///                if the type is not available from the specified provider.
		/// </exception>
		/// <seealso cref= Provider </seealso>
		public static X509StreamParser getInstance(string type, Provider provider)
		{
			try
			{
				X509Util.Implementation impl = X509Util.getImplementation("X509StreamParser", type, provider);

				return createParser(impl);
			}
			catch (NoSuchAlgorithmException e)
			{
				throw new NoSuchParserException(e.Message);
			}
		}

		private static X509StreamParser createParser(X509Util.Implementation impl)
		{
			X509StreamParserSpi spi = (X509StreamParserSpi)impl.getEngine();

			return new X509StreamParser(impl.getProvider(), spi);
		}

		private Provider _provider;
		private X509StreamParserSpi _spi;

		private X509StreamParser(Provider provider, X509StreamParserSpi spi)
		{
			_provider = provider;
			_spi = spi;
		}

		public virtual Provider getProvider()
		{
			return _provider;
		}

		public virtual void init(InputStream stream)
		{
			_spi.engineInit(stream);
		}

		public virtual void init(byte[] data)
		{
			_spi.engineInit(new ByteArrayInputStream(data));
		}

		public virtual object read()
		{
			return _spi.engineRead();
		}

		public virtual Collection readAll()
		{
			return _spi.engineReadAll();
		}
	}

}