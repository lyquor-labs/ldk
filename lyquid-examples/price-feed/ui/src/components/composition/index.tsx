import { cn } from "@/lib/utils";

export const Between = ({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) => {
  return (
    <div className={cn("flex items-center justify-between", className)}>
      {children}
    </div>
  );
};

export const Column = ({
  children,
  className,
}: {
  children: React.ReactNode;
  className?: string;
}) => {
  return <div className={cn("flex flex-col gap-1", className)}>{children}</div>;
};

export const ColumnField = ({
  title,
  children,
  className
}: {
  title: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) => {
  return (
    <Column className={className}>
      {title}
      {children}
    </Column>
  );
};
