<?php

namespace Cube\Packages\Auth\Commands;

use Cube\Commands\BaseCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class AuthSetupCommand extends BaseCommand
{
    protected static $defaultName = 'auth:setup';

    public function configure()
    {
        $this
            ->setDescription('Sets up authentication package')
            ->setHelp('This command helps complete the necessary setup required for authentication');
    }

    public function execute(InputInterface $input, OutputInterface $output)
    {
        $output->writeln('Working!');
        return Command::SUCCESS;
    }
}
