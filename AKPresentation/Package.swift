// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "AKPresentation",
    platforms: [
        .iOS(.v17),
        .macOS(.v14)
    ],
    products: [
        .library(name: "AKPresentation", targets: ["AKPresentation"])
    ],
    dependencies: [
        .package(path: "../AKSecurity/AKSecurity"),
        .package(path: "../AKOpenID4VCI")
    ],
    targets: [
        .target(
            name: "AKPresentation",
            dependencies: [
                .product(name: "AKSecurity", package: "AKSecurity"),
                .product(name: "AKOpenID4VCI", package: "AKOpenID4VCI")
            ],
            path: "Sources/AKPresentation"
        ),
        .testTarget(
            name: "AKPresentationTests",
            dependencies: [
                "AKPresentation",
                .product(name: "AKSecurity", package: "AKSecurity"),
                .product(name: "AKOpenID4VCI", package: "AKOpenID4VCI")
            ],
            path: "Tests/AKPresentationTests"
        )
    ]
)
