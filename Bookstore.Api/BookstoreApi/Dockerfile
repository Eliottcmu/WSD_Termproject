FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Bookstore.csproj", "./"]
RUN dotnet restore "Bookstore.csproj"
COPY . .
RUN dotnet build "Bookstore.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "Bookstore.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "Bookstore.dll"]